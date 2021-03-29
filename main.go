package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type jwtServer struct {
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	Issuer                           string   `json:"issuer"`
	JwksURI                          string   `json:"jwks_uri"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	Version                          string   `json:"version"`
	X509URL                          string   `json:"x509_url"`
}

type jwtPublicKey struct {
	Type      string `json:"kty"`
	Algorithm string `json:"alg"`
	Use       string `json:"use"`
	ID        string `json:"kid"`
	N         string `json:"n"`
	E         string `json:"e"`
}

type jwtPrivateKey struct {
	D      *big.Int
	Primes []*big.Int
}

type handler struct {
	Private jwtPrivateKey
	Public  jwtPublicKey
}

func (h handler) ServeHTTP(c *gin.Context) {
	if c.Request.Method != "GET" {
		c.JSON(http.StatusMethodNotAllowed,
			gin.H{"message": "Method Not Allowed"})
		return
	}

	pathfrags := strings.Split(c.Request.URL.Path, "/")
	if len(pathfrags) <= 1 {
		c.JSON(http.StatusNotFound, gin.H{"message": "Not Found"})
		return
	}
	if pathfrags[1] != ".well-known" {
		c.JSON(http.StatusNotFound,
			gin.H{"message": "Not Found"})
		return
	}
	if len(pathfrags) <= 2 {
		c.JSON(http.StatusNotFound, gin.H{"message": "Not Found"})
		return
	}

	switch pathfrags[2] {
	case "openid-configuration":
		server := jwtServer{
			AuthorizationEndpoint: fmt.Sprintf("https://%s", c.Request.Host),
			IdTokenSigningAlgValuesSupported: []string{
				"RS512",
			},
			Issuer:  fmt.Sprintf("https://%s", c.Request.Host),
			JwksURI: fmt.Sprintf("https://%s/.well-known/jwks_uri", c.Request.Host),
			ResponseTypesSupported: []string{
				"code",
				"id_token",
				"token id_token",
				"none",
			},
			SubjectTypesSupported: []string{
				"public",
			},
			TokenEndpoint: fmt.Sprintf("https://%s", c.Request.Host),
			Version:       "version",
			X509URL:       fmt.Sprintf("https://%s", c.Request.Host),
		}
		c.JSON(http.StatusOK, server)
		return
	case "jwks_uri":
		keys := struct {
			Keys []jwtPublicKey
		}{
			Keys: []jwtPublicKey{
				h.Public,
			},
		}
		c.JSON(http.StatusOK, keys)
		return
	}
}

func main() {
	var pkey jwtPrivateKey
	var pubkey jwtPublicKey

	if _, err := os.Stat("cert.pem"); os.IsNotExist(err) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			panic(err)
		}
		pkey = jwtPrivateKey{D: priv.D, Primes: priv.Primes}
		pemPriv := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(priv),
			},
		)
		pemPub := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: x509.MarshalPKCS1PublicKey(&priv.PublicKey),
			},
		)
		nbytes := priv.PublicKey.N.Bytes()
		ebytes := make([]byte, 4)
		binary.BigEndian.PutUint32(ebytes, uint32(priv.PublicKey.E))
		pubkey = jwtPublicKey{N: base64.StdEncoding.EncodeToString(nbytes),
			Algorithm: "RSA512", Type: "RSA", Use: "sig", ID: "us-wood-1",
			E: base64.StdEncoding.EncodeToString(ebytes)}
		serialNumber, err := rand.Int(rand.Reader,
			new(big.Int).Lsh(big.NewInt(1), 128))
		if err != nil {
			panic(err)
		}
		cert := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{"Acme Co."},
			},
			NotBefore:             time.Now(),
			NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
			KeyUsage:              x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}
		derBytes, err := x509.CreateCertificate(rand.Reader, &cert, &cert, &priv.PublicKey, priv)
		if err != nil {
			panic(err)
		}
		certificate := pem.EncodeToMemory(
			&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: derBytes,
			},
		)
		fp, err := os.Create("cert.pem")
		if err != nil {
			panic(err)
		}
		_, err = fp.Write(pemPriv)
		if err != nil {
			panic(err)
		}
		_, err = fp.Write(pemPub)
		if err != nil {
			panic(err)
		}
		fp.Write(certificate)
	} else {
		fp, err := os.Open("cert.pem")
		if err != nil {
			panic(err)
		}
		data, err := ioutil.ReadAll(fp)
		if err != nil {
			panic(err)
		}
		for {
			block, rest := pem.Decode(data)
			if block == nil {
				break
			}
			switch block.Type {
			case "RSA PRIVATE KEY":
				priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					panic(err)
				}
				pkey = jwtPrivateKey{D: priv.D, Primes: priv.Primes}
			case "RSA PUBLIC KEY":
				pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
				if err != nil {
					panic(err)
				}
				nbytes := pub.N.Bytes()
				ebytes := make([]byte, 4)
				binary.BigEndian.PutUint32(ebytes, uint32(pub.E))
				pubkey = jwtPublicKey{N: base64.StdEncoding.EncodeToString(nbytes),
					Algorithm: "RSA512", Type: "RSA", Use: "sig", ID: "us-wood-1",
					E: base64.StdEncoding.EncodeToString(ebytes)}
			}
			data = rest
		}
	}

	myHandler := handler{Private: pkey, Public: pubkey}
	router := gin.Default()
	router.Any("/.well-known/*rest", func(c *gin.Context) {
		myHandler.ServeHTTP(c)
	})
	router.Run()
}
