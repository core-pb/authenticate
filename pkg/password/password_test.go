package password

import (
	"encoding/hex"
	"fmt"
	"testing"

	"golang.org/x/crypto/argon2"
)

func TestAg(t *testing.T) {
	var (
		pwd  = []byte("password-123-456")
		salt = []byte{
			231, 123, 12, 32, 12, 3, 12, 213,
			37, 23, 54, 56, 65, 76, 170, 66,
		}
		time    = uint32(1)
		mem     = uint32(64 * 1024)
		threads = uint8(1)
		keyLen  = uint32(54)
	)

	{
		b := argon2.IDKey(pwd, salt, time, mem, threads, keyLen)
		s := hex.EncodeToString(b)
		fmt.Println(s)
	}
	{
		b := argon2.IDKey(pwd, salt, time, mem, threads+1, keyLen)
		s := hex.EncodeToString(b)
		fmt.Println(s)
	}

	fmt.Println(1 << 15)
	fmt.Println(1 << 20)
}

// 803ebfe5531ddcbc4f2a2ee951a76110
// 7a2d2cec10edd5e842664b697384649b
// 803ebfe5531ddcbc4f2a2ee951a76110
// 7a2d2cec10edd5e842664b697384649b
// f4ed106ce8c05eedde06efffa6c5e3d9b716d5d9059ebecbae2e19d3e6be93ac
