package probe

import (
	"net"
	"testing"
)

func TestCalculateMSS(t *testing.T) {
	tests := []struct {
		name    string
		mtu     int
		isIPv6  bool
		want    uint16
	}{
		{
			name:   "IPv4 standard ethernet",
			mtu:    1500,
			isIPv6: false,
			want:   1460, // 1500 - 20 (IP) - 20 (TCP)
		},
		{
			name:   "IPv6 standard ethernet",
			mtu:    1500,
			isIPv6: true,
			want:   1440, // 1500 - 40 (IPv6) - 20 (TCP)
		},
		{
			name:   "IPv4 jumbo frames",
			mtu:    9000,
			isIPv6: false,
			want:   8960, // 9000 - 20 - 20
		},
		{
			name:   "IPv6 jumbo frames",
			mtu:    9000,
			isIPv6: true,
			want:   8940, // 9000 - 40 - 20
		},
		{
			name:   "IPv4 small MTU",
			mtu:    576,
			isIPv6: false,
			want:   536, // 576 - 20 - 20
		},
		{
			name:   "IPv6 below minimum",
			mtu:    500,
			isIPv6: true,
			want:   536, // Clamped to minimum
		},
		{
			name:   "IPv4 very small (clamped to minimum)",
			mtu:    100,
			isIPv6: false,
			want:   536, // Minimum MSS
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock interface with the desired MTU
			iface := &net.Interface{
				MTU: tt.mtu,
			}
			got := calculateMSS(iface, tt.isIPv6)
			if got != tt.want {
				t.Errorf("calculateMSS(MTU=%d, IPv6=%v) = %d, want %d",
					tt.mtu, tt.isIPv6, got, tt.want)
			}
		})
	}
}

func TestCalculateMSS_DefaultMTU(t *testing.T) {
	// Test when MTU is 0 or negative (should default to 1500)
	tests := []struct {
		mtu    int
		isIPv6 bool
		want   uint16
	}{
		{mtu: 0, isIPv6: false, want: 1460},
		{mtu: -1, isIPv6: false, want: 1460},
		{mtu: 0, isIPv6: true, want: 1440},
	}

	for _, tt := range tests {
		iface := &net.Interface{MTU: tt.mtu}
		got := calculateMSS(iface, tt.isIPv6)
		if got != tt.want {
			t.Errorf("calculateMSS(MTU=%d, IPv6=%v) = %d, want %d (should default to 1500)",
				tt.mtu, tt.isIPv6, got, tt.want)
		}
	}
}

func TestGenerateTimestampOption(t *testing.T) {
	// Test that timestamp option generates 8 bytes
	ts := generateTimestampOption()
	
	if len(ts) != 8 {
		t.Errorf("generateTimestampOption() length = %d, want 8", len(ts))
	}
	
	// Echo reply should be 0 (bytes 4-7)
	for i := 4; i < 8; i++ {
		if ts[i] != 0 {
			t.Errorf("Echo reply timestamp byte %d = %d, want 0", i, ts[i])
		}
	}
	
	// Timestamp should be non-zero (bytes 0-3)
	allZero := true
	for i := 0; i < 4; i++ {
		if ts[i] != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("Timestamp should not be all zeros")
	}
}

func TestCreateTCPOptions(t *testing.T) {
	// Test that TCP options are created correctly
	iface := &net.Interface{MTU: 1500}
	
	tests := []struct {
		name   string
		isIPv6 bool
	}{
		{"IPv4", false},
		{"IPv6", true},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := createTCPOptions(iface, tt.isIPv6)
			
			if len(opts) == 0 {
				t.Fatal("createTCPOptions() returned empty options")
			}
			
			// Verify key option types are present
			var hasMSS, hasWindowScale, hasTimestamp, hasSACK bool
			for _, opt := range opts {
				switch opt.OptionType {
				case 2: // MSS
					hasMSS = true
					if opt.OptionLength != 4 {
						t.Errorf("MSS option length = %d, want 4", opt.OptionLength)
					}
				case 3: // Window Scale
					hasWindowScale = true
					if opt.OptionLength != 3 {
						t.Errorf("Window Scale option length = %d, want 3", opt.OptionLength)
					}
				case 8: // Timestamp
					hasTimestamp = true
					if opt.OptionLength != 10 {
						t.Errorf("Timestamp option length = %d, want 10", opt.OptionLength)
					}
				case 4: // SACK Permitted
					hasSACK = true
					if opt.OptionLength != 2 {
						t.Errorf("SACK option length = %d, want 2", opt.OptionLength)
					}
				}
			}
			
			if !hasMSS {
				t.Error("TCP options missing MSS")
			}
			if !hasWindowScale {
				t.Error("TCP options missing Window Scale")
			}
			if !hasTimestamp {
				t.Error("TCP options missing Timestamp")
			}
			if !hasSACK {
				t.Error("TCP options missing SACK Permitted")
			}
		})
	}
}
