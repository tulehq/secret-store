package schedule

import (
	"errors"
	"testing"
	"time"
)

func at(s string) time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return t
}

func TestParseRefusesWhatTheUserGuideRefuses(t *testing.T) {
	tests := []struct {
		name  string
		rules Rules
	}{
		{"no schedule", Rules{Duration: "2h"}},
		{"both schedules", Rules{AutomaticallyAfterDays: 3, ScheduleExpression: "rate(3 days)"}},
		{"neither rate nor cron", Rules{ScheduleExpression: "every(3 days)"}},
		{"rate under four hours", Rules{ScheduleExpression: "rate(3 hours)"}},
		{"rate of a day in hours", Rules{ScheduleExpression: "rate(24 hours)"}},
		{"rate over 999 days", Rules{ScheduleExpression: "rate(1000 days)"}},
		{"rate in minutes", Rules{ScheduleExpression: "rate(10 minutes)"}},
		{"rate without a number", Rules{ScheduleExpression: "rate(days)"}},
		{"rate of zero", Rules{ScheduleExpression: "rate(0 days)"}},
		{"rate with a leading zero", Rules{ScheduleExpression: "rate(04 hours)"}},
		{"cron with five fields", Rules{ScheduleExpression: "cron(0 10 * * ?)"}},
		{"cron minutes not 0", Rules{ScheduleExpression: "cron(30 10 * * ? *)"}},
		{"cron year not *", Rules{ScheduleExpression: "cron(0 10 * * ? 2027)"}},
		{"cron every two hours", Rules{ScheduleExpression: "cron(0 /2 * * ? *)"}},
		{"cron every hour", Rules{ScheduleExpression: "cron(0 * * * ? *)"}},
		{"cron hour list", Rules{ScheduleExpression: "cron(0 1,13 * * ? *)"}},
		{"cron hour 24", Rules{ScheduleExpression: "cron(0 24 * * ? *)"}},
		{"cron both days set", Rules{ScheduleExpression: "cron(0 10 1 * MON *)"}},
		{"cron both days ?", Rules{ScheduleExpression: "cron(0 10 ? * ? *)"}},
		{"cron day 32", Rules{ScheduleExpression: "cron(0 10 32 * ? *)"}},
		{"cron month 13", Rules{ScheduleExpression: "cron(0 10 1 13 ? *)"}},
		{"cron bad weekday", Rules{ScheduleExpression: "cron(0 10 ? * FUN *)"}},
		{"cron sixth weekday", Rules{ScheduleExpression: "cron(0 10 ? * MON#6 *)"}},
		{"cron no such date", Rules{ScheduleExpression: "cron(0 10 31 2 ? *)"}},
		{"window not in hours", Rules{ScheduleExpression: "rate(1 day)", Duration: "2d"}},
		{"window of zero", Rules{ScheduleExpression: "rate(1 day)", Duration: "0h"}},
		{"window past the day", Rules{ScheduleExpression: "cron(0 20 * * ? *)", Duration: "5h"}},
		{"window into the next", Rules{ScheduleExpression: "cron(0 0/6 * * ? *)", Duration: "7h"}},
		{"window into the next rate", Rules{ScheduleExpression: "rate(4 hours)", Duration: "5h"}},
		{"window of 25 hours", Rules{AutomaticallyAfterDays: 1, Duration: "25h"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.rules)
			if !errors.Is(err, ErrInvalid) {
				t.Fatalf("Parse(%+v) = %v, want ErrInvalid", tt.rules, err)
			}
		})
	}
}

// nextCases are the examples of the User Guide's "Rotation schedules", and
// the first window each gives after a rotation on Tuesday 2026-11-10 at
// 09:30 UTC.
var nextCases = []struct {
	start string
	end   string
	rules Rules
}{
	// Days: the day N days on, at midnight, to the end of the day.
	{"2026-12-10T00:00:00Z", "2026-12-11T00:00:00Z", Rules{AutomaticallyAfterDays: 30}},
	{"2026-11-20T00:00:00Z", "2026-11-21T00:00:00Z", Rules{ScheduleExpression: "rate(10 days)"}},
	{"2026-11-11T00:00:00Z", "2026-11-12T00:00:00Z", Rules{ScheduleExpression: "rate(1 day)"}},
	{
		"2026-11-11T00:00:00Z",
		"2026-11-11T03:00:00Z",
		Rules{ScheduleExpression: "rate(1 day)", Duration: "3h"},
	},
	// Hours: windows from midnight every N hours, an hour long.
	{"2026-11-10T12:00:00Z", "2026-11-10T13:00:00Z", Rules{ScheduleExpression: "rate(4 hours)"}},
	{"2026-11-10T12:00:00Z", "2026-11-10T13:00:00Z", Rules{ScheduleExpression: "rate(12 hours)"}},
	{
		"2026-11-10T16:00:00Z",
		"2026-11-10T17:00:00Z",
		Rules{ScheduleExpression: "cron(0 /8 * * ? *)"},
	},
	{
		"2026-11-10T16:00:00Z",
		"2026-11-10T17:00:00Z",
		Rules{ScheduleExpression: "cron(0 8/8 * * ? *)"},
	},
	// 2:00, 12:00 and 22:00, and the next day 2:00 again.
	{
		"2026-11-10T12:00:00Z",
		"2026-11-10T13:00:00Z",
		Rules{ScheduleExpression: "cron(0 2/10 * * ? *)"},
	},
	{
		"2026-11-10T16:00:00Z",
		"2026-11-10T17:00:00Z",
		Rules{ScheduleExpression: "cron(0 4/12 * * ? *)"},
	},
	// One hour a day: to the end of that day.
	{
		"2026-11-10T10:00:00Z",
		"2026-11-11T00:00:00Z",
		Rules{ScheduleExpression: "cron(0 10 * * ? *)"},
	},
	{
		"2026-11-14T18:00:00Z",
		"2026-11-15T00:00:00Z",
		Rules{ScheduleExpression: "cron(0 18 ? * SAT *)"},
	},
	{
		"2026-12-01T08:00:00Z",
		"2026-12-02T00:00:00Z",
		Rules{ScheduleExpression: "cron(0 8 1 * ? *)"},
	},
	{
		"2027-01-03T01:00:00Z",
		"2027-01-04T00:00:00Z",
		Rules{ScheduleExpression: "cron(0 1 ? 1/3 SUN#1 *)"},
	},
	{
		"2026-11-30T17:00:00Z",
		"2026-12-01T00:00:00Z",
		Rules{ScheduleExpression: "cron(0 17 L * ? *)"},
	},
	{
		"2026-11-11T08:00:00Z",
		"2026-11-12T00:00:00Z",
		Rules{ScheduleExpression: "cron(0 8 ? * MON-FRI *)"},
	},
	{
		"2026-11-15T16:00:00Z",
		"2026-11-15T18:00:00Z",
		Rules{ScheduleExpression: "cron(0 16 1,15 * ? *)", Duration: "2h"},
	},
	{
		"2026-12-06T00:00:00Z",
		"2026-12-07T00:00:00Z",
		Rules{ScheduleExpression: "cron(0 0 ? * SUN#1 *)"},
	},
	// Starting in January, every 11 months: January and December.
	{
		"2026-12-07T00:00:00Z",
		"2026-12-08T00:00:00Z",
		Rules{ScheduleExpression: "cron(0 0 ? 1/11 2#1 *)"},
	},
	{
		"2026-11-29T09:00:00Z",
		"2026-11-30T00:00:00Z",
		Rules{ScheduleExpression: "cron(0 9 ? * SUNL *)"},
	},
	{
		"2027-01-03T09:00:00Z",
		"2027-01-04T00:00:00Z",
		Rules{ScheduleExpression: "cron(0 9 ? JAN,APR,JUL,OCT 1 *)"},
	},
	{
		"2026-11-11T09:00:00Z",
		"2026-11-12T00:00:00Z",
		Rules{ScheduleExpression: "cron(0 9 1-15 * ? *)"},
	},
	{
		"2028-02-29T09:00:00Z",
		"2028-03-01T00:00:00Z",
		Rules{ScheduleExpression: "cron(0 9 29 2 ? *)"},
	},
}

func TestNextFollowsTheUserGuidesExamples(t *testing.T) {
	base := at("2026-11-10T09:30:00Z")
	for _, tt := range nextCases {
		name := tt.rules.ScheduleExpression
		if name == "" {
			name = "AutomaticallyAfterDays"
		}
		t.Run(name+" "+tt.rules.Duration, func(t *testing.T) {
			s, err := Parse(tt.rules)
			if err != nil {
				t.Fatalf("Parse(%+v): %v", tt.rules, err)
			}
			start, end, ok := s.Next(base)
			if !ok {
				t.Fatal("no next window")
			}
			if !start.Equal(at(tt.start)) || !end.Equal(at(tt.end)) {
				t.Fatalf("Next = %s to %s, want %s to %s", start, end, tt.start, tt.end)
			}
		})
	}
}

func TestTheLastDayOfTheWeekIsEverySaturday(t *testing.T) {
	// "Use L to specify the last day of the week": every Saturday, while
	// <day>L is the last such day of the month.
	tests := []struct{ expr, base, want string }{
		{"cron(0 9 ? * L *)", "2026-11-10T09:30:00Z", "2026-11-14T09:00:00Z"},
		{"cron(0 9 ? * L *)", "2026-11-14T09:30:00Z", "2026-11-21T09:00:00Z"},
		{"cron(0 9 ? * 6L *)", "2026-11-10T09:30:00Z", "2026-11-27T09:00:00Z"},
		{"cron(0 9 ? * FRIL *)", "2026-11-27T09:30:00Z", "2026-12-25T09:00:00Z"},
	}
	for _, tt := range tests {
		s, err := Parse(Rules{ScheduleExpression: tt.expr})
		if err != nil {
			t.Fatalf("Parse(%s): %v", tt.expr, err)
		}
		if start, _, _ := s.Next(at(tt.base)); !start.Equal(at(tt.want)) {
			t.Fatalf("%s after %s = %s, want %s", tt.expr, tt.base, start, tt.want)
		}
	}
}

func TestNextIsStrictlyAfterTheBase(t *testing.T) {
	s, err := Parse(Rules{ScheduleExpression: "cron(0 10 * * ? *)"})
	if err != nil {
		t.Fatal(err)
	}
	// A rotation at the very start of a window waits for the next one.
	start, _, _ := s.Next(at("2026-11-10T10:00:00Z"))
	if want := at("2026-11-11T10:00:00Z"); !start.Equal(want) {
		t.Fatalf("Next = %s, want %s", start, want)
	}
}
