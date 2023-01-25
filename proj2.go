package proj2

// CS 161 Project 2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	"bytes"
	"github.com/cs161-staff/userlib"
	// The JSON library will be useful for serializing go structs.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/json.html.
	"encoding/json"

	// Likewise, useful for debugging, etc.
	"encoding/hex"

	// The Datastore requires UUIDs to store key-value entries.
	// See: https://cs161.org/assets/projects/2/docs/coding_tips/uuid.html.
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys.
	"strings"

	// Want to import errors.
	"errors"

	// Optional. You can remove the "_" there, but please do not touch
	// anything else within the import bracket.
	_ "strconv"
	// if you are looking for fmt, we don't give you fmt, but you can use userlib.DebugMsg.
	// see someUsefulThings() below:
)

// This serves two purposes:
// a) It shows you some useful primitives, and
// b) it suppresses warnings for items not being imported.
// Of course, this function can be deleted.
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var pk userlib.PKEEncKey
	var sk userlib.PKEDecKey
	pk, sk, _ = userlib.PKEKeyGen()
	userlib.DebugMsg("Key is %v, %v", pk, sk)
}

// Helper function: Takes the first 16 bytes and converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// User is the structure definition for a user record.
type User struct {
	Username   string
	DataKey    []byte                  // Parent of other symmetric keys
	UUID       userlib.UUID            // Derived from DataKey, used as key in DataStore
	EncKey     []byte                  // EncKey is used to store User data with confidentiality
	HMACKey    []byte                  // HMACKey is used to provide integrity to stored User data
	PrivateKey userlib.PKEDecKey       // Used to decrypt messages
	SignKey    userlib.DSSignKey       // Used to sign messages
	Files      map[string]userlib.UUID // Map of filename->fileUUID for files the user has access to
	Keys       map[userlib.UUID][]byte // Map of fileUUID->symmetricEncKey for all the file parts the user has access to
}

// File is the structure definition for a file record.
type File struct {
	FileUUID      userlib.UUID
	EncryptionKey []byte
	HMACKey       []byte
	Users         *UserTree
	Data          []byte
	Appends       []userlib.UUID
}

// UserTree is the structure definition for the Users that have access to a file
// Parent field can't be *UserTree type because it prevents marshalling because of possible cycles
// It only cost me one of my drop days to figure this out lol
type UserTree struct {
	Username string
	Parent   string
	Children []*UserTree
}

// Invite is a struct that holds a file UUID/key pair
type Invite struct {
	FileUUID userlib.UUID
	FileKey  []byte
}

// InitUser will be called a single time to initialize a new user.
func InitUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata
	keysize := uint32(userlib.AESKeySizeBytes)

	// To access the user & their files, we rely on the password being the only thing that's secret
	// Therefore, we derive DataKey/UUID from username & password hash
	userdata.Username = username
	userdata.DataKey = userlib.Argon2Key([]byte(password), []byte(username), keysize)
	userdata.UUID = bytesToUUID(userdata.DataKey)

	// We use HashKDF to derive all the other symmteric keys from DataKey since it's faster
	userdata.EncKey, _ = userlib.HashKDF(userdataptr.DataKey, []byte("EncKey"))
	userdata.HMACKey, _ = userlib.HashKDF(userdataptr.DataKey, []byte("HMACKey"))

	// Cut AES and HMAC keys to proper size
	userdata.EncKey = userdata.EncKey[:userlib.AESKeySizeBytes]
	userdata.HMACKey = userdata.HMACKey[:16]

	// generate a key pair for asymmetric encryption and digital sigs
	publicKey, privateKey, _ := userlib.PKEKeyGen()
	signKey, verifyKey, _ := userlib.DSKeyGen()

	// store public keys on KeyServer
	_ = userlib.KeystoreSet(username+"Encrypt", publicKey)
	_ = userlib.KeystoreSet(username+"Verify", verifyKey)

	// store private keys in user structure
	userdata.PrivateKey = privateKey
	userdata.SignKey = signKey

	// set up file map and key map
	userdata.Files = make(map[string]userlib.UUID)
	userdata.Keys = make(map[userlib.UUID][]byte)

	// Marshal
	marshalledUser, _ := json.Marshal(userdata)
	// Pad plaintext
	marshalledUser, _ = pkcs7Pad(marshalledUser, userlib.AESBlockSizeBytes)
	// Encrypt-then-MAC
	// [ msg = enc(userData) || HMAC(enc(userData)) ]
	encryptedUser := userlib.SymEnc(userdata.EncKey, userlib.RandomBytes(16), marshalledUser) // encrypt
	encryptedUserHMAC, err := userlib.HMACEval(userdata.HMACKey, encryptedUser)               // generate HMAC
	userlib.DatastoreSet(userdata.UUID, append(encryptedUser, encryptedUserHMAC...))          // tag & store

	// return pointer to user structure
	return &userdata, nil
}

// GetUser is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/getuser.html
func GetUser(username string, password string) (userdataptr *User, err error) {
	var userdata User
	userdataptr = &userdata

	// Generate DataKey & username/password
	DataKey := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySizeBytes))
	// Generate UUID from DataKey
	UUID := bytesToUUID(DataKey)
	// Generate symmetric keys
	EncKey, _ := userlib.HashKDF(DataKey, []byte("EncKey"))
	HMACKey, _ := userlib.HashKDF(DataKey, []byte("HMACKey"))
	EncKey = EncKey[:userlib.AESKeySizeBytes]
	HMACKey = HMACKey[:16]

	// Load user
	encryptedData, ok := userlib.DatastoreGet(UUID)
	if !ok {
		return nil, ErrUserNotFound
	}
	// Catch corruptions that cause the file to be shorter than the minimum for decryption
	if len(encryptedData) < userlib.AESBlockSizeBytes {
		return nil, ErrDataCorruption
	}

	// Separate userdata & HMAC
	encryptedUser := encryptedData[:len(encryptedData)-64]
	storedHMAC := encryptedData[len(encryptedData)-64:]

	// Compare HMACs to verify integrity
	calculatedHMAC, _ := userlib.HMACEval(HMACKey, encryptedUser)
	if !userlib.HMACEqual(storedHMAC, calculatedHMAC) {
		return nil, ErrDataCorruption
	}

	// Decrypt
	decryptedUser := userlib.SymDec(EncKey, encryptedUser)
	// Unpad
	decryptedUser, err = pkcs7Unpad(decryptedUser, userlib.AESBlockSizeBytes)
	if err != nil {
		return nil, err
	}
	// Unmarshal
	_ = json.Unmarshal(decryptedUser, userdataptr)

	return userdataptr, nil
}

// StoreFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/storefile.html
func (userdata *User) StoreFile(filename string, data []byte) (err error) {
	fileUUID, fileExists := userdata.Files[filename]
	var file File
	var tmpFile *File

	// If file doesn't already exist in datastore, we "create" it
	if !fileExists {
		// fileUUID can be randomly generated since they're stored in a User struct, which is stored with integrity
		fileUUID = uuid.New()
		fileKey := userlib.RandomBytes(userlib.AESKeySizeBytes)
		userdata.Files[filename] = fileUUID
		userdata.Keys[fileUUID] = fileKey

		// Set File members
		file.FileUUID = fileUUID
		file.EncryptionKey, _ = userlib.HashKDF(fileKey, []byte("EncryptionKey"))
		file.HMACKey, _ = userlib.HashKDF(fileKey, []byte("HMACKey"))
		file.EncryptionKey = file.EncryptionKey[:userlib.AESKeySizeBytes]
		file.HMACKey = file.HMACKey[:16]

		// Initialize UserTree
		file.Users = &UserTree{
			Username: userdata.Username,
			Parent:   "",
			Children: []*UserTree{},
		}
	} else { // If the file exists, it needs to be overwritten without affecting which Users have access
		tmpFile, err = userdata.loadFileStruct(filename)

		// If the user has lost access to a file, then we don't try to overwrite it.
		if tmpFile.Users.DepthFirstSearch(userdata.Username) == nil {
			fileUUID = uuid.New()
			fileKey := userlib.RandomBytes(userlib.AESKeySizeBytes)
			userdata.Files[filename] = fileUUID
			userdata.Keys[fileUUID] = userlib.RandomBytes(userlib.AESKeySizeBytes)

			// Set file Members
			file.FileUUID = fileUUID
			file.EncryptionKey, _ = userlib.HashKDF(fileKey, []byte("EncryptionKey"))
			file.HMACKey, _ = userlib.HashKDF(fileKey, []byte("HMACKey"))
			file.EncryptionKey = file.EncryptionKey[:userlib.AESKeySizeBytes]
			file.HMACKey = file.HMACKey[:16]

			// Initialize UserTree
			file.Users = &UserTree{
				Username: userdata.Username,
				Parent:   "",
				Children: []*UserTree{},
			}
		} else {
			file = *tmpFile
			file.Appends = nil
			// Delete any appends on old file
			for _, append := range tmpFile.Appends {
				userlib.DatastoreDelete(append)
			}

		}
	}

	// Copy data into file
	file.Data = data

	err = userdata.storeFileStruct(&file)
	if err != nil {
		return err
	}

	// Update User
	// Marshal
	marshalledUser, _ := json.Marshal(userdata)
	// Pad plaintext
	marshalledUser, _ = pkcs7Pad(marshalledUser, userlib.AESBlockSizeBytes)
	// Encrypt-then-MAC
	// [ msg = enc(userData) || HMAC(enc(userData)) ]
	encryptedUser := userlib.SymEnc(userdata.EncKey, userlib.RandomBytes(16), marshalledUser) // encrypt
	encryptedUserHMAC, err := userlib.HMACEval(userdata.HMACKey, encryptedUser)               // generate HMAC
	userlib.DatastoreSet(userdata.UUID, append(encryptedUser, encryptedUserHMAC...))          // tag & store

	return
}

// AppendFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/appendfile.html
func (userdata *User) AppendFile(filename string, data []byte) (err error) {
	var file File
	fileptr := &file

	// Load File struct
	fileptr, err = userdata.loadFileStruct(filename)
	if err != nil {
		return err
	}

	if fileptr.Users.DepthFirstSearch(userdata.Username) == nil {
		return ErrNoPermission
	}

	// Pad append
	data, err = pkcs7Pad(data, userlib.AESBlockSizeBytes)
	if err != nil {
		return err
	}
	// Encrypt append
	data = userlib.SymEnc(fileptr.EncryptionKey, userlib.RandomBytes(userlib.AESKeySizeBytes), data)
	// Generate HMAC & tag encrypted file
	dataHMAC, _ := userlib.HMACEval(fileptr.HMACKey, data)

	// Store the encrypted/tagged Append in the DataStore
	appendUUID := uuid.New()
	file.Appends = append(file.Appends, appendUUID)
	userlib.DatastoreSet(appendUUID, append(data, dataHMAC...))

	// Update File in DataStore
	fileptr.Appends = append(fileptr.Appends, appendUUID)

	err = userdata.storeFileStruct(fileptr)
	if err != nil {
		return err
	}

	return
}

// LoadFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/loadfile.html
func (userdata *User) LoadFile(filename string) (dataBytes []byte, err error) {
	fileptr, err := userdata.loadFileStruct(filename)
	if err != nil {
		return nil, err
	}

	// Verify User has access
	if fileptr.Users.DepthFirstSearch(userdata.Username) == nil {
		return nil, ErrNoPermission
	}

	// Load data from file
	dataBytes = fileptr.Data
	for _, appendUUID := range fileptr.Appends {
		// Load append
		encryptedAppend, appendExists := userlib.DatastoreGet(appendUUID)
		if !appendExists {
			return nil, ErrAppendNotFound
		}
		// Catch corruptions that cause the file to be shorter than the minimum for decryption
		if len(encryptedAppend) < userlib.AESBlockSizeBytes {
			return nil, ErrDataCorruption
		}

		// Separate data & HMAC
		encryptedData := encryptedAppend[:len(encryptedAppend)-64]
		storedHMAC := encryptedAppend[len(encryptedAppend)-64:]

		// Compare HMACs to verify integrity
		calculatedHMAC, _ := userlib.HMACEval(fileptr.HMACKey, encryptedData)
		if !userlib.HMACEqual(storedHMAC, calculatedHMAC) {
			return nil, ErrDataCorruption
		}

		// Decrypt
		decryptedAppend := userlib.SymDec(fileptr.EncryptionKey, encryptedData)
		// Unpad
		decryptedAppend, err = pkcs7Unpad(decryptedAppend, userlib.AESBlockSizeBytes)
		if err != nil {
			return nil, err
		}

		dataBytes = append(dataBytes, decryptedAppend...)
	}

	return dataBytes, nil
}

// ShareFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/sharefile.html
func (userdata *User) ShareFile(filename string, recipient string) (accessToken uuid.UUID, err error) {
	// Load file to be shared
	file, err := userdata.loadFileStruct(filename)
	if err != nil {
		return uuid.Nil, err
	}

	// Verify that User has permission to share file. If so, add the recipient to the UserTree as a child of User.
	sender := file.Users.DepthFirstSearch(userdata.Username)
	if sender != nil {
		sender.Children = append(sender.Children, &UserTree{
			Username: recipient,
			Parent:   userdata.Username,
			Children: []*UserTree{},
		})
	} else {
		return uuid.Nil, ErrNoPermission
	}

	// Store File changes
	err = userdata.storeFileStruct(file)
	if err != nil {
		return uuid.Nil, err
	}

	// Create invite
	invite := Invite{
		FileUUID: file.FileUUID,
		FileKey:  userdata.Keys[file.FileUUID],
	}

	// Marshall invite
	marshalledInvite, _ := json.Marshal(invite)

	// Load recipient public key for public key encryption
	publicKey, ok := userlib.KeystoreGet(recipient + "Encrypt")
	if !ok {
		return uuid.Nil, ErrPublicKeyNotFound
	}

	// Encrypt invite
	encryptedInvite, _ := userlib.PKEEnc(publicKey, marshalledInvite)

	// Sign invite (provides authenticity and integrity)
	signKey := userdata.SignKey
	inviteSignature, _ := userlib.DSSign(signKey, encryptedInvite)
	message := append(encryptedInvite, inviteSignature...)

	// Store invite
	accessToken = uuid.New()
	userlib.DatastoreSet(accessToken, message)

	return
}

// ReceiveFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/receivefile.html
func (userdata *User) ReceiveFile(filename string, sender string, accessToken uuid.UUID) error {
	// Get invite
	message, ok := userlib.DatastoreGet(accessToken)
	if !ok {
		return ErrInviteMissing
	}

	// Get verification key
	verifyKey, ok := userlib.KeystoreGet(sender + "Verify")
	if !ok {
		return ErrVerifyKeyNotFound
	}
	// Verify invite
	encryptedInvite := message[:len(message)-256]
	signature := message[len(message)-256:]
	err := userlib.DSVerify(verifyKey, encryptedInvite, signature)
	if err != nil {
		return err
	}

	// Decrypt invite
	var invite Invite
	inviteptr := &invite
	decryptedInvite, err := userlib.PKEDec(userdata.PrivateKey, encryptedInvite)
	if err != nil {
		return err
	}
	json.Unmarshal(decryptedInvite, inviteptr)

	// Throw an error if recipient already has a file with the given filename
	_, ok = userdata.Files[filename]
	if ok {
		return ErrFileExists
	}

	userdata.Files[filename] = invite.FileUUID
	userdata.Keys[invite.FileUUID] = invite.FileKey

	return nil
}

// RevokeFile is documented at:
// https://cs161.org/assets/projects/2/docs/client_api/revokefile.html
func (userdata *User) RevokeFile(filename string, targetUsername string) (err error) {
	// load file
	file, err := userdata.loadFileStruct(filename)

	// verify targetUsername has access
	if file != nil && file.Users != nil {
		targetUser := file.Users.DepthFirstSearch(targetUsername)
		if targetUser == nil {
			return ErrNoPermission
		}

		// remove user access
		parent := file.Users.DepthFirstSearch(targetUser.Parent)
		if parent == nil {
			return ErrUserNotFound
		}
		i := 0
		for _, child := range parent.Children {
			if child.Username != targetUsername {
				parent.Children[i] = child
				i++
			}
		}
		parent.Children = parent.Children[:i]

		// update file
		err = userdata.storeFileStruct(file)
		if err != nil {
			return err
		}
	}

	return
}

/*
********************************************
**           HELPER FUNCTIONS             **
********************************************
 */

// pkcs7Pad right-pads the given byte slice with 1 to n bytes, where
// n is the block size. The size of the result is x times n, where x
// is at least 1.
func pkcs7Pad(b []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, errors.New("invalid blocksize")
	}
	if b == nil || len(b) == 0 {
		return nil, errors.New("invalid PKCS7 data")
	}
	n := blocksize - (len(b) % blocksize)
	pb := make([]byte, len(b)+n)
	copy(pb, b)
	copy(pb[len(b):], bytes.Repeat([]byte{byte(n)}, n))
	return pb, nil
}

// pkcs7Unpad validates and unpads data from the given bytes slice.
// The returned value will be 1 to n bytes smaller depending on the
// amount of padding, where n is the block size.
func pkcs7Unpad(b []byte, blocksize int) ([]byte, error) {
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize := errors.New("invalid blocksize")
	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data := errors.New("invalid PKCS7 data (empty or not padded)")
	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding := errors.New("invalid padding on input")
	if blocksize <= 0 {
		return nil, ErrInvalidBlockSize
	}
	if b == nil || len(b) == 0 {
		return nil, ErrInvalidPKCS7Data
	}
	if len(b)%blocksize != 0 {
		return nil, ErrInvalidPKCS7Padding
	}
	c := b[len(b)-1]
	n := int(c)
	if n == 0 || n > len(b) {
		return nil, ErrInvalidPKCS7Padding
	}
	for i := 0; i < n; i++ {
		if b[len(b)-n+i] != c {
			return nil, ErrInvalidPKCS7Padding
		}
	}
	return b[:len(b)-n], nil
}

// This function is used to securely load a single File struct for a User from the DataStore
// This involves decryption and message authentication.
func (userdata *User) loadFileStruct(filename string) (fileptr *File, err error) {
	// Load fileUUID. Throw an error if User doesn't have a file named 'filename'
	fileUUID, ok := userdata.Files[filename]
	if !ok {
		return nil, ErrFileNotFound
	}

	// Load fileKey. Throw an error if User doesn't have key to file
	fileKey, ok := userdata.Keys[fileUUID]
	if !ok {
		return nil, ErrFileKeyNotFound
	}

	// Derive symmetric encryption/HMAC key from fileKey
	encryptionKey, _ := userlib.HashKDF(fileKey, []byte("EncryptionKey"))
	HMACKey, _ := userlib.HashKDF(fileKey, []byte("HMACKey"))
	// Cut keys to proper length
	encryptionKey = encryptionKey[:userlib.AESKeySizeBytes]
	HMACKey = HMACKey[:16]

	// Load file
	encryptedFile, ok := userlib.DatastoreGet(fileUUID)
	if !ok {
		return nil, ErrFileNotFound
	}
	// Catch corruptions that cause the file to be shorter than the minimum for decryption
	if len(encryptedFile) < userlib.AESBlockSizeBytes {
		return nil, ErrDataCorruption
	}

	// Separate data & HMAC
	encryptedData := encryptedFile[:len(encryptedFile)-64]
	storedHMAC := encryptedFile[len(encryptedFile)-64:]

	// Compare HMACs to verify integrity
	calculatedHMAC, _ := userlib.HMACEval(HMACKey, encryptedData)
	if !userlib.HMACEqual(storedHMAC, calculatedHMAC) {
		return nil, ErrDataCorruption
	}

	// Decrypt
	decryptedData := userlib.SymDec(encryptionKey, encryptedData)
	// Unpad
	decryptedData2, err := pkcs7Unpad(decryptedData, userlib.AESBlockSizeBytes)
	if err != nil {
		return nil, err
	}
	// Unmarshal
	var file File
	fileptr = &file
	_ = json.Unmarshal(decryptedData2, fileptr)

	return
}

// This function encrypts, tags, and stores a File struct for a User on the DataStore.
func (userdata *User) storeFileStruct(fileptr *File) (err error) {
	// Marshal new file
	marshalledFile, err := json.Marshal(*fileptr)
	if err != nil {
		return err
	}

	// Pad plaintext
	marshalledFile, _ = pkcs7Pad(marshalledFile, userlib.AESBlockSizeBytes)
	// Encrypt file
	encryptedFile := userlib.SymEnc(fileptr.EncryptionKey, userlib.RandomBytes(userlib.AESKeySizeBytes), marshalledFile)
	// Generate HMAC & tag encrypted file
	encryptedFileHMAC, _ := userlib.HMACEval(fileptr.HMACKey, encryptedFile)
	userlib.DatastoreSet(fileptr.FileUUID, append(encryptedFile, encryptedFileHMAC...))

	return
}

// Depth first search on UserTrees
// Been a long time since 61a
func (node *UserTree) DepthFirstSearch(username string) *UserTree {
	if node.Username == username {
		return node
	}
	for _, child := range node.Children {
		found := child.DepthFirstSearch(username)
		if found != nil {
			return found
		}
	}
	return nil
}

/*
************************************
**            ERRORS              **
************************************
 */
var (
	// Datastore errors
	ErrUserNotFound      = errors.New("Username or password is incorrect!")
	ErrDataCorruption    = errors.New("Data was corrupted!")
	ErrFileNotFound      = errors.New("File not found!")
	ErrFileKeyNotFound   = errors.New("File key not found!")
	ErrAppendNotFound    = errors.New("Append not found!")
	ErrPublicKeyNotFound = errors.New("Public key not found!")
	ErrNoPermission      = errors.New("User doesn't have permission!")
	ErrInviteMissing     = errors.New("Can't find invite!")
	ErrVerifyKeyNotFound = errors.New("Verification key not found!")
	ErrFileExists        = errors.New("File exists!")

	// PKCS7 Errors
	// ErrInvalidBlockSize indicates hash blocksize <= 0.
	ErrInvalidBlockSize = errors.New("invalid blocksize")
	// ErrInvalidPKCS7Data indicates bad input to PKCS7 pad or unpad.
	ErrInvalidPKCS7Data = errors.New("invalid PKCS7 data (empty or not padded)")
	// ErrInvalidPKCS7Padding indicates PKCS7 unpad fails to bad input.
	ErrInvalidPKCS7Padding = errors.New("invalid padding on input")
)
