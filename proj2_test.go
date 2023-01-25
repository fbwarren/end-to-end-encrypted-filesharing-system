package proj2

// You MUST NOT change these default imports.  ANY additional imports it will
// break the autograder and everyone will be sad.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"

	"github.com/cs161-staff/userlib"
	"github.com/google/uuid"
	_ "github.com/google/uuid"
)

func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}

func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}

/*func TestGetUser(t *testing.T) {
	clear()
	userlib.SetDebugStatus(true)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("", err)
		return
	}

	// Basic GetUser test
	_, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get existing user.", err)
		return
	}

	// Corruption detection test
	UUID := generateUUID("alice", "fubar")
	userdata, _ := userlib.DatastoreGet(UUID)
	userlib.DatastoreSet(UUID, userdata[:len(userdata)-1])
	_, err = GetUser("alice", "fubar")
	if err == nil {
		t.Error("Failed to detect data corruption.", err)
		return
	}

	//
	userlib.DatastoreSet(UUID, userdata[:1])
	_, err = GetUser("alice", "fubar")
	if err == nil {
		t.Error("Failed to detect data corruption.", err)
		return
	}

	// Test that we can't get a user after they've been deleted
	userlib.DatastoreClear()
	_, err = GetUser("alice", "fubar")
	if err == nil {
		t.Error("Accidentally retrieved a deleted user.", err)
		return
	}

	// Test getting user that never existed
	_, err = GetUser("bob", "rabuf")
	if err == nil {
		t.Error("Accidentally retrieved a user that never existed")
		return
	}
}*/

func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	file := []byte("This is a test.")
	u.StoreFile("file1", file)

	// Basic store/load test
	loadedFile, err := u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to upload and download", err)
		return
	}
	if !reflect.DeepEqual(loadedFile, file) {
		t.Error("Downloaded file is not the same", file, loadedFile)
		return
	}

	// Basic append test
	apnd := []byte(" This is an append.")
	file = append(file, apnd...)
	err = u.AppendFile("file1", apnd)
	if err != nil {
		t.Error("Failed to append.", err)
		return
	}
	loadedFile, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file.", err)
		return
	}
	if !reflect.DeepEqual(loadedFile, file) {
		t.Error("Downloaded file is not the same", loadedFile, file)
		return
	}

	/*// Multiple appends
	apnd = []byte(" This the second append.")
	file = append(file, apnd...)
	err = u.AppendFile("file1", apnd)
	if err != nil {
		t.Error("Failed to append.", err)
		return
	}
	loadedFile, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file.", err)
		return
	}
	if !reflect.DeepEqual(loadedFile, file) {
		t.Error("Downloaded file is not the same", loadedFile, file)
		return
	}*/
}

func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a nonexistent file", err2)
		return
	}
}

func TestBasicShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test.")
	u.StoreFile("file1", v)

	var v2 []byte
	var accessToken uuid.UUID

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	accessToken, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
}

func TestSessions(t *testing.T) {
	clear()
	alice1, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	alice2, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get user", err)
		return
	}
	file := []byte("This is a file.")
	err = alice1.StoreFile("file", file)
	if err != nil {
		t.Error("Failed to store file", err)
	}
	load1, err := alice1.LoadFile("file")
	if err != nil {
		t.Error("Failed to load file", err)
	}
	load2, err := alice2.LoadFile("file")
	if err != nil {
		t.Error("Failed to load file", err)
	}
	if !reflect.DeepEqual(file, load1) {
		t.Error("File is not the same", file, load1)
		return
	}
	if !reflect.DeepEqual(load1, load2) {
		t.Error("File is not the same", load1, load2)
	}
}

func TestRevoke(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	bob, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	file := []byte("This is a file.")
	err = alice.StoreFile("file", file)
	if err != nil {
		t.Error("Failed to store file", err)
	}
	accessToken, err := alice.ShareFile("file", "bob")
	if err != nil {
		t.Error("Failed to share file.", err)
	}
	err = bob.ReceiveFile("file1", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive file.", err)
	}
	loadedFile, err := bob.LoadFile("file1")
	if err != nil {
		t.Error("Failed to load file.", err)
	}
	if !reflect.DeepEqual(loadedFile, file) {
		t.Error("File is not the same", loadedFile, file)
	}
	err = alice.RevokeFile("file", "bob")
	if err != nil {
		t.Error("Error revoking file.", err)
	}
	loadedFile, err = bob.LoadFile("file")
	if err == nil {
		t.Error("Loaded file whose access has been revoked.", err)
	}
}

/*
func TestModel(t *testing.T) {
	clear()
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	bob, err := InitUser("bob", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	file := []byte("This is a file.")
}
*/

/*func TestComprehensive(t *testing.T) {
	alice, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	bob, err := InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err)
		return
	}
	charles, err := InitUser("charles", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	devin, err := InitUser("devin", "foobar")
	if err != nil {
		t.Error("Failed to initialize bob", err)
		return
	}

	file := []byte("This is the initial file.")

	// Alice stores the initial file and shares it with Bob.
	alice.StoreFile("file", file)
	accessToken, err := alice.ShareFile("file", "bob")
	if err != nil {
		t.Error("Failed to share the file", err)
	}

	// Bob receives the file using the accessToken from Alice, but he wants it to be named "alicesFile"
	bob.ReceiveFile("alicesFile", "alice", accessToken)
	if err != nil {
		t.Error("Failed to receive the file", err)
	}
	receivedFile, err := bob.LoadFile("alicesFile")
	if err != nil {
		t.Error("Failed to load the file", err)
	}

	// Alice appends the file.
	append1 := []byte("Alice's append.")
	file = append(file, append1...)
	alice.AppendFile("file", append1)
	if err != nil {
		t.Error("Failed to append the file", err)
	}
	// Bob should be able to see this addition immediately.
	receivedFile, err = bob.LoadFile("alicesFile")
	if err != nil {
		t.Error("Failed to load the file", err)
	}
	if !reflect.DeepEqual(receivedFile, file) {
		t.Error("Shared file is not the same", receivedFile, file)
		return
	}

	// Bob can also give access to other people
	accessToken, err = bob.ShareFile("alicesFile", "charles")
	if err != nil {
		t.Error("Failed to share the file", err)
	}
	charles.ReceiveFile("file", "bob", accessToken)
	if err != nil {
		t.Error("Failed to receive the file", err)
	}
	accessToken, err = bob.ShareFile("alicesFile", "devin")
	if err != nil {
		t.Error("Failed to share the file", err)
	}
	devin.ReceiveFile("file", "bob", accessToken)
	if err != nil {
		t.Error("Failed to receive the file", err)
	}

	// If Alice revokes Bob's access, all the people he granted access should also lose access
	alice.RevokeFile("file", "bob")
	receivedFile, err = bob.LoadFile("alicesFile")
	if err == nil {
		t.Error("Loaded a file a user didn't have access to", err)
	}
	receivedFile, err = charles.LoadFile("file")
	if err == nil {
		t.Error("Loaded a file a user didn't have access to", err)
	}
	receivedFile, err = devin.LoadFile("file")
	if err == nil {
		t.Error("Loaded a file a user didn't have access to", err)
	}




	clear()
	_ = bob
	_ = charles
	_ = devin
}*/

/*
************************
**      HELPERS       **
************************
 */
func generateUUID(username string, password string) (UUID userlib.UUID) {
	DataKey := userlib.Argon2Key([]byte(password), []byte(username), uint32(userlib.AESKeySizeBytes))
	for x := range UUID {
		UUID[x] = DataKey[x]
	}
	return
}
