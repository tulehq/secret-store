package secret

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"

	"github.com/gasmod/gas"

	"tule.dev/secret-store/internal/contracts"
	"tule.dev/secret-store/internal/schedule"
	"tule.dev/secret-store/internal/smapi"
)

// The constraints of RotateSecret's members in the API reference
// (RotateSecret, RotationRulesType).
const (
	minTokenLen          = 32
	maxTokenLen          = 64
	maxLambdaARNLen      = 2048
	minAfterDays         = 1
	maxAfterDays         = 1000
	minDurationLen       = 2
	maxDurationLen       = 3
	maxScheduleLen       = 256
	durationPattern      = `[0-9]+h`
	scheduleExprPattern  = `[0-9A-Za-z\(\)#\?\*\-\/, ]+`
	notServedWithoutFunc = " is not implemented by this service without a functions endpoint " +
		"(TULE_Store_FunctionsEndpoint) to invoke rotation functions through."
)

var (
	durationRe     = regexp.MustCompile(`^` + durationPattern + `$`)
	scheduleExprRe = regexp.MustCompile(`^` + scheduleExprPattern + `$`)
	// functionARNRe is a Lambda function's ARN, unqualified or with a
	// version or alias, as Lambda's model gives its FunctionArn. It is this
	// service's check: Secrets Manager's model bounds RotationLambdaARN's
	// length only.
	functionARNRe = regexp.MustCompile(
		`^arn:aws:lambda:[a-z0-9-]+:(\d{12}):function:[a-zA-Z0-9-_]{1,64}(:(\$LATEST|[a-zA-Z0-9-_]+))?$`,
	)
)

func (m *Module) rotateSecret(ctx gas.Context) error {
	if !m.rotations.Available() {
		return smapi.ErrNotImplemented("RotateSecret" + notServedWithoutFunc)
	}
	req, err := decode[smapi.RotateSecretRequest](ctx)
	if err != nil {
		return err
	}
	if err = checkRotateRequest(req); err != nil {
		return err
	}
	rules, err := rotationRules(req.RotationRules)
	if err != nil {
		return err
	}

	keys := optional(nil, "secretsmanager:RotationLambdaARN", req.RotationLambdaARN)
	if req.RotateImmediately != nil {
		keys = optional(keys, "secretsmanager:RotateImmediately",
			strconv.FormatBool(*req.RotateImmediately))
	}
	if req.RotationRules != nil {
		keys = optional(keys, "secretsmanager:ModifyRotationRules", "true")
	}
	sctx := m.guardSecret(ctx, "RotateSecret", req.SecretID, keys,
		func(found *contracts.SecretDetail) error {
			return m.checkInvoke(ctx, req.RotationLambdaARN, found)
		})

	out, err := m.rotations.Rotate(sctx, contracts.StartRotationInput{
		SecretID:  req.SecretID,
		LambdaARN: req.RotationLambdaARN,
		Token:     req.ClientRequestToken,
		Rules:     rules,
		TestOnly:  req.RotateImmediately != nil && !*req.RotateImmediately,
	})
	if err != nil {
		return err
	}
	return smapi.Write(ctx, smapi.CreateSecretResponse{
		SecretRefResponse: secretRef(out.SecretRef),
		VersionID:         out.VersionID,
	})
}

// checkRotateRequest refuses a RotateSecret request this service does not
// serve or whose members break the model's constraints, before anything is
// evaluated.
func checkRotateRequest(req smapi.RotateSecretRequest) error {
	if err := requireSecretID(req.SecretID); err != nil {
		return err
	}
	if t := req.ClientRequestToken; t != "" {
		if len(t) < minTokenLen {
			return smapi.ErrTooShort("clientRequestToken", t, minTokenLen)
		}
		if len(t) > maxTokenLen {
			return smapi.ErrTooLong("clientRequestToken", t, maxTokenLen)
		}
	}
	if req.ExternalSecretRotationRoleArn != nil || req.ExternalSecretRotationMetadata != nil {
		return smapi.ErrInvalidParameter("Managed external secrets are not supported by this " +
			"service; rotate with a RotationLambdaARN.")
	}
	if fn := req.RotationLambdaARN; fn != "" {
		if len(fn) > maxLambdaARNLen {
			return smapi.ErrTooLong("rotationLambdaARN", fn, maxLambdaARNLen)
		}
		if !functionARNRe.MatchString(fn) {
			return smapi.ErrInvalidParameter("RotationLambdaARN must be the ARN of a Lambda " +
				"function, arn:aws:lambda:<region>:<account>:function:<name>.")
		}
	}
	return nil
}

// rotationRules checks the request's RotationRules against the model's
// constraints and the User Guide's schedule rules (schedule.Parse), and
// returns them, or nil when the request has none.
func rotationRules(in *smapi.RotationRules) (*schedule.Rules, error) {
	if in == nil {
		return nil, nil //nolint:nilnil // no rules is not an error
	}
	r := schedule.Rules{
		AutomaticallyAfterDays: derefInt(in.AutomaticallyAfterDays),
		Duration:               deref(in.Duration),
		ScheduleExpression:     deref(in.ScheduleExpression),
	}
	if err := checkRulesModel(in); err != nil {
		return nil, err
	}
	if _, err := schedule.Parse(r); err != nil {
		if errors.Is(err, schedule.ErrInvalid) {
			return nil, smapi.ErrInvalidParameter(
				strings.TrimPrefix(err.Error(), schedule.ErrInvalid.Error()+": "))
		}
		return nil, err
	}
	return &r, nil
}

// checkRulesModel checks the members of RotationRules the request gives
// against RotationRulesType's range, lengths and patterns.
func checkRulesModel(in *smapi.RotationRules) error {
	if in.AutomaticallyAfterDays != nil {
		d := *in.AutomaticallyAfterDays
		if d < minAfterDays {
			return smapi.ErrTooSmall("rotationRules.automaticallyAfterDays", d, minAfterDays)
		}
		if d > maxAfterDays {
			return smapi.ErrTooLarge("rotationRules.automaticallyAfterDays", d, maxAfterDays)
		}
	}
	if in.Duration != nil {
		if err := checkString("rotationRules.duration", *in.Duration,
			minDurationLen, maxDurationLen, durationRe, durationPattern); err != nil {
			return err
		}
	}
	if in.ScheduleExpression != nil {
		return checkString("rotationRules.scheduleExpression", *in.ScheduleExpression,
			1, maxScheduleLen, scheduleExprRe, scheduleExprPattern)
	}
	return nil
}

// checkString holds value, the member field, to the model's lengths and
// pattern.
func checkString(field, value string, minLen, maxLen int, re *regexp.Regexp, pattern string) error {
	switch {
	case len(value) < minLen:
		return smapi.ErrTooShort(field, value, minLen)
	case len(value) > maxLen:
		return smapi.ErrTooLong(field, value, maxLen)
	case !re.MatchString(value):
		return smapi.ErrPattern(field, value, pattern)
	default:
		return nil
	}
}

func derefInt(n *int64) int64 {
	if n == nil {
		return 0
	}
	return *n
}

// checkInvoke checks lambda:InvokeFunction on the rotation function the
// request names, or the one found has stored when it names none. With no
// function at all there is nothing to check, and the store refuses the
// request.
func (m *Module) checkInvoke(
	ctx context.Context,
	requested string,
	found *contracts.SecretDetail,
) error {
	fn := requested
	if fn == "" && found != nil && found.Rotation != nil {
		fn = found.Rotation.LambdaARN
	}
	if fn == "" {
		return nil
	}
	match := functionARNRe.FindStringSubmatch(fn)
	if match == nil {
		return errors.New("the stored rotation function " + fn + " is not a function ARN")
	}
	return m.authz.CheckInvoke(ctx, fn, match[1])
}

func (m *Module) cancelRotateSecret(ctx gas.Context) error {
	if !m.rotations.Available() {
		return smapi.ErrNotImplemented("CancelRotateSecret" + notServedWithoutFunc)
	}
	req, err := decode[smapi.SecretIDRequest](ctx)
	if err != nil {
		return err
	}
	if err = requireSecretID(req.SecretID); err != nil {
		return err
	}
	sctx := m.guardSecret(ctx, "CancelRotateSecret", req.SecretID, nil)

	out, err := m.rotations.Cancel(sctx, req.SecretID)
	if err != nil {
		return err
	}
	return smapi.Write(ctx, smapi.CreateSecretResponse{
		SecretRefResponse: secretRef(out.SecretRef),
		VersionID:         out.VersionID,
	})
}

// wireRotation reports a secret's rotation configuration as DescribeSecret
// and ListSecrets do.
func wireRotation(d *contracts.RotationDetail) smapi.Rotation {
	if d == nil {
		return smapi.Rotation{}
	}
	enabled := d.Enabled
	out := smapi.Rotation{
		RotationEnabled:   &enabled,
		RotationLambdaARN: d.LambdaARN,
		LastRotatedDate:   smapi.Stamp(d.LastRotatedDate),
		NextRotationDate:  smapi.Stamp(d.NextRotationDate),
	}
	if r := d.Rules; r != nil {
		out.RotationRules = &smapi.RotationRules{}
		if r.AutomaticallyAfterDays != 0 {
			days := r.AutomaticallyAfterDays
			out.RotationRules.AutomaticallyAfterDays = &days
		}
		if r.Duration != "" {
			dur := r.Duration
			out.RotationRules.Duration = &dur
		}
		if r.ScheduleExpression != "" {
			expr := r.ScheduleExpression
			out.RotationRules.ScheduleExpression = &expr
		}
	}
	return out
}
