package firewall

import (
	"context"
	"testing"

	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"
)

func Test_firewall_ServeDNS(t *testing.T) {
	type fields struct {
		Next  plugin.Handler
		Rules []Rule
		Zones []string
	}
	type args struct {
		ctx context.Context
		w   dns.ResponseWriter
		r   *dns.Msg
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    int
		wantErr bool
	}{
		// TODO: Add test cases. (@ihac)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := firewall{
				Next:  tt.fields.Next,
				Rules: tt.fields.Rules,
				Zones: tt.fields.Zones,
			}
			got, err := f.ServeDNS(tt.args.ctx, tt.args.w, tt.args.r)
			if (err != nil) != tt.wantErr {
				t.Errorf("firewall.ServeDNS() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("firewall.ServeDNS() = %v, want %v", got, tt.want)
			}
		})
	}
}
