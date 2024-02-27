package main

import (
	"strings"
	"testing"

	"github.com/elvisgraho/jwt-cracker-go/utils"
)

func TestCrackJWTToken(t *testing.T) {
	tests := []struct {
		name  string
		token string
		alg   string
		want  string
	}{
		{
			name:  "HS256",
			token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.5mhBHqs5_DTLdINd9p5m7ZJ6XD0Xc55kIaCRY5r6HRA",
			want:  "test",
		},
		{
			name:  "HS384",
			token: "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.KOZqnJ-wEzC-JvqqIHGKBIGgbYHH2Fej71TpBctnIguBkf3EdSYiwuRMSz35uY8E",
			want:  "test",
		},
		{
			name:  "HS512",
			token: "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.VXfjNdZn9mDxRYhiaCi8rYYtcuNe3KCfK3LvggWSaHwjZsag9ugMOuDPOeeBD3oNhK-cOkTvRLy_ERbgnEyxYA",
			want:  "test",
		},
	}

	for _, tt := range tests {
		isTokenValid, algorithm := utils.ValidateToken(tt.token)

		if !isTokenValid && tt.token == "" {
			t.Errorf("TestCrackJWTToken() Invalid Token!")
		}

		jwtParts := strings.Split(tt.token, ".")

		t.Run(tt.name, func(t *testing.T) {
			got := utils.Brute(utils.DefaultAlphabet, utils.DefaultMaxSecretLength, algorithm, jwtParts)
			if got != tt.want {
				t.Errorf("Brute() = %v, want %v", got, tt.want)
			}
		})
	}
}
