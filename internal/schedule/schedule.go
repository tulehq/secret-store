// Package schedule reads a secret's rotation rules, AutomaticallyAfterDays
// or a rate() or cron() ScheduleExpression with an optional Duration, as the
// Secrets Manager User Guide ("Rotation schedules") defines them, and works
// out the rotation windows they give.
//
// A rotation window is the span Secrets Manager may rotate the secret in. It
// always starts on the hour, in UTC, and lasts Duration, or by default one
// hour for a schedule in hours and to the end of the UTC day for a schedule
// in days. It must not reach into the next UTC day or the next window.
package schedule

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Rules are a secret's rotation rules as RotateSecret takes them: one of
// AutomaticallyAfterDays and ScheduleExpression, and an optional Duration.
// A zero AutomaticallyAfterDays and an empty string are absent.
type Rules struct {
	ScheduleExpression     string
	Duration               string
	AutomaticallyAfterDays int64
}

// ErrInvalid is what every rule Parse refuses wraps. Its message says what
// is wrong, in words a caller can act on.
var ErrInvalid = errors.New("schedule: invalid rotation rules")

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// The bounds the User Guide sets ("Rotation schedules"): "You can rotate a
// secret as often as every four hours. The maximum rotation period is 999
// days." The window is "as small as one hour".
const (
	minHours    = 4
	maxRateDays = 999
	day         = 24 * time.Hour
)

// Schedule is a parsed set of rules. The zero value is not usable; Parse
// returns one.
type Schedule struct {
	cron *cron
	// days is the period of a schedule in days, AutomaticallyAfterDays or
	// rate(N days), and 0 for any other.
	days int
	// window is the window's length, or 0 for "to the end of the UTC day".
	window time.Duration
}

// Parse reads r. It fails with an error wrapping ErrInvalid when r names no
// schedule or both, or when its expression or window breaks the User
// Guide's rules.
func Parse(r Rules) (*Schedule, error) {
	hasDays, hasExpr := r.AutomaticallyAfterDays != 0, r.ScheduleExpression != ""
	switch {
	case hasDays && hasExpr:
		return nil, invalid("You can set AutomaticallyAfterDays or ScheduleExpression " +
			"in RotationRules, but not both.")
	case !hasDays && !hasExpr:
		return nil, invalid("RotationRules must set AutomaticallyAfterDays or ScheduleExpression.")
	}

	s := &Schedule{days: int(r.AutomaticallyAfterDays)}
	if hasExpr {
		if err := s.parseExpression(r.ScheduleExpression); err != nil {
			return nil, err
		}
	}
	if err := s.parseWindow(r.Duration); err != nil {
		return nil, err
	}
	return s, nil
}

// parseExpression reads a rate() or cron() ScheduleExpression.
func (s *Schedule) parseExpression(expr string) error {
	if inner, ok := enclosed(expr, "rate("); ok {
		return s.parseRate(inner)
	}
	inner, ok := enclosed(expr, "cron(")
	if !ok {
		return invalid("ScheduleExpression %q is neither a rate() nor a cron() expression.", expr)
	}
	c, err := parseCron(inner)
	if err != nil {
		return err
	}
	// An expression whose days never come, such as the 31st of February,
	// has no window to rotate in.
	if _, found := c.next(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)); !found {
		return invalid("ScheduleExpression %q matches no date.", expr)
	}
	s.cron = c
	return nil
}

// enclosed returns what expr has between open and a closing parenthesis.
func enclosed(expr, open string) (string, bool) {
	inner, ok := strings.CutPrefix(expr, open)
	if !ok {
		return "", false
	}
	return strings.CutSuffix(inner, ")")
}

// parseRate reads the inside of rate(Value Unit), where Value is a positive
// integer and Unit is hour, hours, day or days.
//
// A rate in hours is read as cron(0 0/Value * * ? *): its windows start at
// midnight UTC and every Value hours after it, resetting each day, as the
// User Guide says of a rate() expression ("the rotation window starts at
// midnight") and of increments of hours in cron ("resets each day"). Values
// from 24 hours up are refused, as a schedule in days is what they mean;
// the User Guide gives no rate in hours above 12.
func (s *Schedule) parseRate(inner string) error {
	value, unit, ok := strings.Cut(inner, " ")
	n, err := number(value, 1, maxInt)
	if !ok || err != nil {
		return invalid("rate(%s) needs a positive whole number and a unit, as in rate(10 days).",
			inner)
	}
	switch unit {
	case "hour", "hours":
		return s.rateInHours(inner, n)
	case "day", "days":
		if n > maxRateDays {
			return invalid("The maximum rotation period is %d days; rate(%s) is longer.",
				maxRateDays, inner)
		}
		s.days = n
		return nil
	default:
		return invalid("rate(%s) has the unit %q; it must be hour, hours, day or days.",
			inner, unit)
	}
}

// maxInt bounds the numbers a rate() reads.
const maxInt = 1 << 30

func (s *Schedule) rateInHours(inner string, n int) error {
	if n < minHours {
		return invalid(
			"You can rotate a secret as often as every %d hours; rate(%s) is more often.",
			minHours,
			inner,
		)
	}
	if n >= 24 {
		return invalid("rate(%s) is a schedule in days; write it as rate(N days).", inner)
	}
	s.cron = everyHours(0, n)
	return nil
}

// parseWindow reads Duration, "<hours>h", and checks the window it gives
// against the schedule: at least an hour, and not reaching into the next UTC
// day or the next window.
func (s *Schedule) parseWindow(duration string) error {
	if duration == "" {
		if s.inHours() {
			s.window = time.Hour
		}
		return nil
	}
	hours, ok := strings.CutSuffix(duration, "h")
	n, err := number(hours, 1, 24)
	if !ok || err != nil {
		return invalid("Duration %q must be a whole number of hours from 1 to 24, such as 3h.",
			duration)
	}
	w := time.Duration(n) * time.Hour

	starts := []int{0}
	if s.cron != nil {
		starts = s.cron.hours
	}
	if err = checkWindow(starts, w, duration); err != nil {
		return err
	}
	s.window = w
	return nil
}

// checkWindow fails when a window of w from one of the hours starts reaches
// into the next UTC day or the next start.
func checkWindow(starts []int, w time.Duration, duration string) error {
	for i, h := range starts {
		if time.Duration(h)*time.Hour+w > day {
			return invalid(
				"A rotation window of %s starting at %02d:00 extends into the next UTC day.",
				duration,
				h,
			)
		}
		if i+1 < len(starts) && time.Duration(starts[i+1]-h)*time.Hour < w {
			return invalid(
				"A rotation window of %s extends into the next rotation window.",
				duration,
			)
		}
	}
	return nil
}

// inHours reports whether the schedule is one in hours: more than one window
// a day.
func (s *Schedule) inHours() bool {
	return s.cron != nil && len(s.cron.hours) > 1
}

// Next returns the first rotation window after a rotation at base: its
// start and its end. ok is false when there is none, which Parse rules out.
//
// For a schedule in days, AutomaticallyAfterDays or rate(N days), it is
// the UTC day N days after base's, "based on the previous rotation" as the
// API reference says of AutomaticallyAfterDays. For a cron() expression or a
// rate in hours, it is the first window that starts after base.
func (s *Schedule) Next(base time.Time) (start, end time.Time, ok bool) {
	base = base.UTC()
	if s.cron != nil {
		start, ok = s.cron.next(base)
	} else {
		midnight := time.Date(base.Year(), base.Month(), base.Day(), 0, 0, 0, 0, time.UTC)
		start, ok = midnight.AddDate(0, 0, s.days), true
	}
	if !ok {
		return time.Time{}, time.Time{}, false
	}
	if s.window == 0 {
		end = time.Date(start.Year(), start.Month(), start.Day()+1, 0, 0, 0, 0, time.UTC)
	} else {
		end = start.Add(s.window)
	}
	return start, end, true
}

// cron is a parsed cron(Minutes Hours Day-of-month Month Day-of-week Year)
// expression. Minutes is always 0 and Year always *, so a match is a day and
// an hour.
type cron struct {
	dom    *dayOfMonth
	dow    *dayOfWeek
	hours  []int
	months [13]bool
}

// everyHours is the hours field "from/step".
func everyHours(from, step int) *cron {
	c := &cron{hours: stepHours(from, step), dom: &dayOfMonth{}}
	for d := 1; d <= 31; d++ {
		c.dom.days[d] = true
	}
	for m := 1; m <= 12; m++ {
		c.months[m] = true
	}
	return c
}

func stepHours(from, step int) []int {
	var hours []int
	for h := from; h <= 23; h += step {
		hours = append(hours, h)
	}
	return hours
}

// parseCron reads the six fields of a Secrets Manager cron expression, with
// the values and wildcards the User Guide's table ("Cron expression
// requirements in Secrets Manager") allows in each.
func parseCron(inner string) (*cron, error) {
	fields := strings.Fields(inner)
	if len(fields) != 6 {
		return nil, invalid("cron(%s) must have six fields: Minutes Hours Day-of-month "+
			"Month Day-of-week Year.", inner)
	}
	if fields[0] != "0" {
		return nil, invalid("The Minutes field of a cron expression must be 0, since rotation " +
			"windows start on the hour.")
	}
	if fields[5] != "*" {
		return nil, invalid("The Year field of a cron expression must be *, since rotation " +
			"schedules can't be more than a year apart.")
	}

	c := &cron{}
	var err error
	if c.hours, err = parseHours(fields[1]); err != nil {
		return nil, err
	}
	if err = parseMonths(fields[3], &c.months); err != nil {
		return nil, err
	}

	domAny, dowAny := fields[2] == "?", fields[4] == "?"
	if domAny == dowAny {
		return nil, invalid("Exactly one of the Day-of-month and Day-of-week fields must be ?.")
	}
	if dowAny {
		c.dom, err = parseDayOfMonth(fields[2])
	} else {
		c.dow, err = parseDayOfWeek(fields[4])
	}
	if err != nil {
		return nil, err
	}
	return c, nil
}

// parseHours reads the Hours field: an hour 0 to 23, or an increment,
// "from/step" or "/step" (from 0), at least four hours apart.
func parseHours(f string) ([]int, error) {
	from, step, isStep := strings.Cut(f, "/")
	if !isStep {
		h, err := number(f, 0, 23)
		if err != nil {
			return nil, invalid("The Hours field %q must be an hour from 0 to 23, or an increment "+
				"such as 2/10.", f)
		}
		return []int{h}, nil
	}
	start := 0
	if from != "" {
		var err error
		if start, err = number(from, 0, 23); err != nil {
			return nil, invalid("The Hours field %q starts at no hour from 0 to 23.", f)
		}
	}
	n, err := number(step, 1, 23)
	if err != nil {
		return nil, invalid("The Hours field %q has no increment from 1 to 23.", f)
	}
	if n < minHours {
		return nil, invalid("You can rotate a secret as often as every %d hours; the Hours "+
			"field %q is more often.", minHours, f)
	}
	return stepHours(start, n), nil
}

var monthNames = []string{
	"JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
}

var dayNames = []string{"SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"}

// parseMonths reads the Month field: 1 to 12 or JAN to DEC, with , - * and /.
func parseMonths(f string, months *[13]bool) error {
	return parseList(f, 1, 12, monthNames, "Month", func(v int) { months[v] = true })
}

// dayOfMonth is the Day-of-month field: the days it lists, and L, the last
// day of the month.
type dayOfMonth struct {
	days [32]bool
	last bool
}

// parseDayOfMonth reads the Day-of-month field: 1 to 31 with , - * and /,
// or L.
func parseDayOfMonth(f string) (*dayOfMonth, error) {
	d := &dayOfMonth{}
	if f == "L" {
		d.last = true
		return d, nil
	}
	if err := parseList(
		f,
		1,
		31,
		nil,
		"Day-of-month",
		func(v int) { d.days[v] = true },
	); err != nil {
		return nil, err
	}
	return d, nil
}

// dayOfWeek is the Day-of-week field, 1 (SUN) to 7 (SAT): the days it lists,
// <day>#<n>, the nth such day of the month, and <day>L, the last such day
// of the month. L alone is the last day of the week, SAT, every week.
type dayOfWeek struct {
	nth   [8]int
	days  [8]bool
	lastO [8]bool
}

// parseDayOfWeek reads the Day-of-week field.
func parseDayOfWeek(f string) (*dayOfWeek, error) {
	d := &dayOfWeek{}
	if f == "L" {
		// "Use L to specify the last day of the week": SAT, every week.
		d.days[7] = true
		return d, nil
	}
	if name, n, ok := strings.Cut(f, "#"); ok {
		v, err := value(name, 1, 7, dayNames)
		nth, nErr := number(n, 1, 5)
		if err != nil || nErr != nil {
			return nil, invalid(
				"The Day-of-week field %q must be <day>#<1 to 5>, such as TUE#3.",
				f,
			)
		}
		d.nth[v] = nth
		return d, nil
	}
	if name, ok := strings.CutSuffix(f, "L"); ok && name != "" {
		v, err := value(name, 1, 7, dayNames)
		if err != nil {
			return nil, invalid("The Day-of-week field %q must be <day>L, such as SUNL.", f)
		}
		d.lastO[v] = true
		return d, nil
	}
	if err := parseList(
		f,
		1,
		7,
		dayNames,
		"Day-of-week",
		func(v int) { d.days[v] = true },
	); err != nil {
		return nil, err
	}
	return d, nil
}

// parseList reads a comma-separated list of *, a value, a range a-b, or an
// increment of any of those, x/step, calling set with each value it names.
func parseList(f string, lo, hi int, names []string, field string, set func(int)) error {
	for item := range strings.SplitSeq(f, ",") {
		from, to, step, err := parseItem(item, lo, hi, names)
		if err != nil {
			return invalid("The %s field %q has %s.", field, f, err.Error())
		}
		for v := from; v <= to; v += step {
			set(v)
		}
	}
	return nil
}

// parseItem reads one item of a list: the values from and to it spans, by
// step.
func parseItem(item string, lo, hi int, names []string) (from, to, step int, err error) {
	rng, stepStr, hasStep := strings.Cut(item, "/")
	step = 1
	if hasStep {
		if step, err = number(stepStr, 1, hi); err != nil {
			return 0, 0, 0, errors.New("no valid increment")
		}
	}
	a, b, isRange := strings.Cut(rng, "-")
	switch {
	case rng == "*":
		return lo, hi, step, nil
	case isRange:
		from, aErr := value(a, lo, hi, names)
		to, bErr := value(b, lo, hi, names)
		if aErr != nil || bErr != nil || from > to {
			return 0, 0, 0, fmt.Errorf("a range that is not from %d to %d", lo, hi)
		}
		return from, to, step, nil
	}
	v, err := value(rng, lo, hi, names)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("a value that is not from %d to %d", lo, hi)
	}
	if hasStep {
		return v, hi, step, nil
	}
	return v, v, step, nil
}

// value reads a number from lo to hi, or one of names, which stand for lo
// onwards.
func value(s string, lo, hi int, names []string) (int, error) {
	if i := slices.Index(names, strings.ToUpper(s)); i >= 0 {
		return lo + i, nil
	}
	return number(s, lo, hi)
}

func number(s string, lo, hi int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi || s != strconv.Itoa(n) {
		return 0, fmt.Errorf("not a number from %d to %d: %q", lo, hi, s)
	}
	return n, nil
}

// searchDays bounds how far ahead next looks for a matching day: two leap
// years apart and some, so a schedule on the 29th of February is found.
const searchDays = 9 * 366

// next returns the first match after after.
func (c *cron) next(after time.Time) (time.Time, bool) {
	d := time.Date(after.Year(), after.Month(), after.Day(), 0, 0, 0, 0, time.UTC)
	for range searchDays {
		if c.months[d.Month()] && c.matchesDay(d) {
			for _, h := range c.hours {
				if start := d.Add(time.Duration(h) * time.Hour); start.After(after) {
					return start, true
				}
			}
		}
		d = d.AddDate(0, 0, 1)
	}
	return time.Time{}, false
}

func (c *cron) matchesDay(d time.Time) bool {
	lastOfMonth := time.Date(d.Year(), d.Month()+1, 0, 0, 0, 0, 0, time.UTC).Day()
	if c.dom != nil {
		return c.dom.days[d.Day()] || (c.dom.last && d.Day() == lastOfMonth)
	}
	wd := int(d.Weekday()) + 1 // 1 is SUN
	switch {
	case c.dow.days[wd]:
		return true
	case c.dow.nth[wd] > 0:
		return (d.Day()-1)/7+1 == c.dow.nth[wd]
	case c.dow.lastO[wd]:
		return d.Day()+7 > lastOfMonth
	default:
		return false
	}
}
