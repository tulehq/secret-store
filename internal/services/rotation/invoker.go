package rotation

import (
	"context"
	"fmt"

	"tule.dev/functions/serviceinvoke"
)

// functionsInvoker invokes rotation functions through the functions
// service's service-invoke endpoint, as ServicePrincipal, with the secret's
// ARN as aws:SourceArn and the store's account as aws:SourceAccount, the
// context the function policy is evaluated with.
type functionsInvoker struct {
	client  *serviceinvoke.Client
	account string
}

// NewFunctionsInvoker returns an Invoker calling client for the secrets of
// account.
func NewFunctionsInvoker(client *serviceinvoke.Client, account string) Invoker {
	return &functionsInvoker{client: client, account: account}
}

// Invoke invokes function synchronously with event. A function that fails is
// no error: its StepResult has FunctionError set.
func (f *functionsInvoker) Invoke(
	ctx context.Context,
	function string,
	event []byte,
	secretARN string,
) (*StepResult, error) {
	res, err := f.client.Invoke(ctx, function, ServicePrincipal, event,
		serviceinvoke.WithSourceArn(secretARN),
		serviceinvoke.WithSourceAccount(f.account))
	if err != nil {
		return nil, fmt.Errorf("rotation: %w", err)
	}
	return &StepResult{
		RequestID:     res.RequestID,
		FunctionError: res.FunctionError,
		Payload:       res.Payload,
	}, nil
}
