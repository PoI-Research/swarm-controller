package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"strings"

	"net/http"

	"github.com/gin-gonic/gin"
)

var publicKey string = ""
var privateKey string = ""

func getPublicKey(c *gin.Context) {
	key, _ := getKeys()
	c.IndentedJSON(http.StatusOK, gin.H{"publicKey": key})
}

func getAccountSignature(c *gin.Context) {
	coinbase := c.Param("coinbase")
	sign := signAccount(coinbase)

	c.IndentedJSON(http.StatusOK, gin.H{"signature": sign})
}

func signAccount(coinbase string) string {
	_, key := getKeys()
	privateKey, err := decodePrivateKey(key)
	if err != nil {
		panic(err)
	}

	msgHash := sha256.New()
	msgHash.Write([]byte(coinbase))
	msgHashSum := msgHash.Sum(nil)
	signature, _ := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, msgHashSum)

	return base64.StdEncoding.EncodeToString(signature)
}

func generateKeys() *rsa.PrivateKey {
	// Generate RSA key.
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	return key
}

func saveKeys(key *rsa.PrivateKey) {
	// Extract public component.
	publicKey = encodePublickey(&key.PublicKey)

	// Extract private component.
	privateKey = encodePrivateKey(key)
}

func encodePublickey(pubKey *rsa.PublicKey) string {
	// Marshal public key to PEM format.
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: x509.MarshalPKCS1PublicKey(pubKey),
	})

	return string(publicKeyPEM)
}

func encodePrivateKey(privKey *rsa.PrivateKey) string {
	// Marshal private key to PEM format.
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	})

	return string(privateKeyPEM)
}

func retrieveKeys() (string, string) {
	return publicKey, privateKey
}

func decodePrivateKey(key string) (*rsa.PrivateKey, error) {
	r := strings.NewReader(key)
	pemBytes, err := ioutil.ReadAll(r)

	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing the key")
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}

	return nil, err
}

func getKeys() (string, string) {
	pubKey, privKey := retrieveKeys()

	if pubKey == "" || privKey == "" {
		saveKeys(generateKeys())

		return retrieveKeys()
	}

	return pubKey, privKey
}

func main() {
	router := gin.Default()
	router.GET("/getPublicKey", getPublicKey)
	router.GET("/getSignature/:coinbase", getAccountSignature)

	router.Run(":8080")
}
