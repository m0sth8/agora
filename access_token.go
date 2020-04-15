package agora

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/crc32"
	"io"
	"math/rand"
	"sort"
	"time"
)

/*
AccessToken implementation based on https://github.com/AgoraIO/Tools/blob/master/DynamicKey/AgoraDynamicKey/go/src/AccessToken/AccessToken.go code provided by AgoraIO team.
*/

const VersionLength = 3
const AppIdLength = 32
const dk6version = "006"

type Privileges uint16

const (
	PrivilegeJoinChannel        Privileges = 1
	PrivilegePublishAudioStream Privileges = 2
	PrivilegePublishVideoStream Privileges = 3
	PrivilegePublishDataStream  Privileges = 4

	PrivilegePublishAudioCdn           Privileges = 5
	PrivilegePublishVideoCdn           Privileges = 6
	PrivilegeRequestPublishAudioStream Privileges = 7
	PrivilegeRequestPublishVideoStream Privileges = 8
	PrivilegeRequestPublishDataStream  Privileges = 9
	PrivilegeInvitePublishAudioStream  Privileges = 10
	PrivilegeInvitePublishVideoStream  Privileges = 11
	PrivilegeInvitePublishDataStream   Privileges = 12

	PrivilegeAdministrateChannel Privileges = 101
	PrivilegeLoginRtm            Privileges = 1000
)

type AccessToken struct {
	appID          string
	appCertificate string
	channelName    string
	uidStr         string
	ts             uint32
	salt           uint32
	message        map[Privileges]uint32
	signature      string
	crcChannelName uint32
	crcUid         uint32
	msgRawContent  string
}

func random(min int, max int) int {
	rand.Seed(time.Now().UnixNano())
	return rand.Intn(max-min) + min
}

func NewAccessToken(appID, appCertificate, channelName string, uid uint32) *AccessToken {
	var uidStr string
	if uid == 0 {
		uidStr = ""
	} else {
		uidStr = fmt.Sprintf("%d", uid)
	}
	return NewAccessTokenStrUID(appID, appCertificate, channelName, uidStr)
}

func NewAccessTokenStrUID(appID, appCertificate, channelName string, uid string) *AccessToken {
	ts := uint32(time.Now().Unix()) + 24*3600
	salt := uint32(random(1, 99999999))
	message := make(map[Privileges]uint32)
	return &AccessToken{appID, appCertificate, channelName, uid, ts, salt, message, "", 0, 0, ""}
}

func NewAccessTokenFromString(originToken string) (*AccessToken, error) {
	originVersion := originToken[:VersionLength]
	if originVersion != dk6version {
		return nil, fmt.Errorf("supported version %s, origin version %s", dk6version, originVersion)
	}

	originAppID := originToken[VersionLength:(VersionLength + AppIdLength)]
	originContent := originToken[(VersionLength + AppIdLength):]
	originContentDecoded, err := base64.StdEncoding.DecodeString(originContent)
	if err != nil {
		return nil, err
	}

	signature_, crc_channel_name_, crc_uid_, msg_raw_content_, err := unPackContent(originContentDecoded)
	if err != nil {
		return nil, err
	}
	token := AccessToken{}
	token.appID = originAppID
	token.signature = signature_
	token.crcChannelName = crc_channel_name_
	token.crcUid = crc_uid_
	token.msgRawContent = msg_raw_content_

	salt_, ts_, messages_, err := unPackMessages(token.msgRawContent)
	if err != nil {
		return nil, err
	}
	token.salt = salt_
	token.ts = ts_
	token.message = messages_

	return &token, nil
}

func (token *AccessToken) AddPrivilege(privilege Privileges, expireTimestamp time.Time) {
	pri := privilege
	token.message[pri] = uint32(expireTimestamp.Unix())
}

func (token *AccessToken) Build() (string, error) {
	ret := ""
	version := dk6version

	bufM := new(bytes.Buffer)
	if err := packUint32(bufM, token.salt); err != nil {
		return ret, err
	}
	if err := packUint32(bufM, token.ts); err != nil {
		return ret, err
	}
	if err := packMapUint32(bufM, token.message); err != nil {
		return ret, err
	}
	bytesM := bufM.Bytes()

	bufVal := new(bytes.Buffer)
	bufVal.WriteString(token.appID)
	bufVal.WriteString(token.channelName)
	bufVal.WriteString(token.uidStr)
	bufVal.Write(bytesM)

	bytesVal := bufVal.Bytes()

	bufSig := hmac.New(sha256.New, []byte(token.appCertificate))
	bufSig.Write(bytesVal)
	bytesSig := bufSig.Sum(nil)

	crc32q := crc32.MakeTable(0xedb88320)
	crcChannelName := crc32.Checksum([]byte(token.channelName), crc32q)
	crcUid := crc32.Checksum([]byte(token.uidStr), crc32q)

	bufContent := new(bytes.Buffer)
	if err := packString(bufContent, string(bytesSig)); err != nil {
		return ret, err
	}
	if err := packUint32(bufContent, crcChannelName); err != nil {
		return ret, err
	}
	if err := packUint32(bufContent, crcUid); err != nil {
		return ret, err
	}
	if err := packString(bufContent, string(bytesM)); err != nil {
		return ret, err
	}
	bytesContent := bufContent.Bytes()

	ret = version + token.appID + base64.StdEncoding.EncodeToString(bytesContent)
	return ret, nil
}

func packUint16(w io.Writer, n uint16) error {
	return binary.Write(w, binary.LittleEndian, n)
}

func packUint32(w io.Writer, n uint32) error {
	return binary.Write(w, binary.LittleEndian, n)
}

func packString(w io.Writer, s string) error {
	err := packUint16(w, uint16(len(s)))
	if err != nil {
		return err
	}
	_, err = w.Write([]byte(s))
	return err
}

func packHexString(w io.Writer, s string) error {
	b, err := hex.DecodeString(s)
	if err != nil {
		return err
	}
	return packString(w, string(b))
}

func packExtra(w io.Writer, extra map[uint16]string) error {
	keys := []int{}
	if err := packUint16(w, uint16(len(extra))); err != nil {
		return err
	}
	for k := range extra {
		keys = append(keys, int(k))
	}
	//should sorted keys
	sort.Ints(keys)

	for _, k := range keys {
		v := extra[uint16(k)]
		if err := packUint16(w, uint16(k)); err != nil {
			return err
		}
		if err := packString(w, v); err != nil {
			return err
		}
	}
	return nil
}

func packMapUint32(w io.Writer, extra map[Privileges]uint32) error {
	keys := []Privileges{}
	if err := packUint16(w, uint16(len(extra))); err != nil {
		return err
	}
	for k := range extra {
		keys = append(keys, k)
	}
	//should be sorted keys
	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	for _, k := range keys {
		v := extra[k]
		if err := packUint16(w, uint16(k)); err != nil {
			return err
		}
		if err := packUint32(w, v); err != nil {
			return err
		}
	}
	return nil
}

func unPackUint16(r io.Reader) (uint16, error) {
	var n uint16
	err := binary.Read(r, binary.LittleEndian, &n)
	return n, err
}

func unPackUint32(r io.Reader) (uint32, error) {
	var n uint32
	err := binary.Read(r, binary.LittleEndian, &n)
	return n, err
}

func unPackString(r io.Reader) (string, error) {
	n, err := unPackUint16(r)
	if err != nil {
		return "", err
	}

	buf := make([]byte, n)
	r.Read(buf)
	s := string(buf[:])
	return s, err
}

func unPackContent(buff []byte) (string, uint32, uint32, string, error) {
	in := bytes.NewReader(buff)
	sig, err := unPackString(in)
	if err != nil {
		return "", 0, 0, "", err
	}

	crcChannelName, err := unPackUint32(in)
	if err != nil {
		return "", 0, 0, "", err
	}
	crcUid, err := unPackUint32(in)
	if err != nil {
		return "", 0, 0, "", err
	}
	m, err := unPackString(in)
	if err != nil {
		return "", 0, 0, "", err
	}

	return sig, crcChannelName, crcUid, m, nil
}

func unPackMessages(msgStr string) (uint32, uint32, map[Privileges]uint32, error) {
	msgMap := make(map[Privileges]uint32)

	msgByte := []byte(msgStr)
	in := bytes.NewReader(msgByte)

	salt, err := unPackUint32(in)
	if err != nil {
		return 0, 0, msgMap, err
	}
	ts, err := unPackUint32(in)
	if err != nil {
		return 0, 0, msgMap, err
	}

	length, err := unPackUint16(in)
	if err != nil {
		return 0, 0, msgMap, err
	}
	for i := uint16(0); i < length; i++ {
		key, err := unPackUint16(in)
		if err != nil {
			return 0, 0, msgMap, err
		}
		value, err := unPackUint32(in)
		if err != nil {
			return 0, 0, msgMap, err
		}
		msgMap[Privileges(key)] = value
	}

	return salt, ts, msgMap, nil
}
