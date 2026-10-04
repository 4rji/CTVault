package fetch

import "golang.org/x/time/rate"

func newTestLimiter(rps float64) *rate.Limiter { return rate.NewLimiter(rate.Limit(rps), 1) }
