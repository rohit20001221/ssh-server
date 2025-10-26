package core

const (
	SSH_MSG_DISCONNECT      byte = 1
	SSH_MSG_IGNORE          byte = 2
	SSH_MSG_UNIMPLEMENTED   byte = 3
	SSH_MSG_DEBUG           byte = 4
	SSH_MSG_SERVICE_REQUEST byte = 5
	SSH_MSG_SERVICE_ACCEPT  byte = 6
	SSH_MSG_KEXINIT         byte = 20
	SSH_MSG_NEWKEYS         byte = 21
)

func GetMessageCode(code byte) []byte {
	return []byte{code}
}
