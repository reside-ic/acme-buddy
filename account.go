package main

import (
	"bytes"
	"crypto"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
	"os"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/registration"
)

type Account struct {
	Server       string                 `json:"server"`
	Email        string                 `json:"email"`
	KeyData      []byte                 `json:"private_key"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

func NewAccount(server string, email string) (*Account, error) {
	key, err := certcrypto.GeneratePrivateKey(certcrypto.EC256)
	if err != nil {
		return nil, err
	}

	buffer := new(bytes.Buffer)
	err = pem.Encode(buffer, certcrypto.PEMBlock(key))
	if err != nil {
		return nil, err
	}

	return &Account{
		Server:  server,
		Email:   email,
		KeyData: buffer.Bytes(),
		key:     key,
	}, nil
}

func ReadAccount(file string) (*Account, error) {
	jsonBytes, err := ioutil.ReadFile(file)
	if err != nil {
		return nil, err
	}

	account := new(Account)
	err = json.Unmarshal(jsonBytes, account)
	if err != nil {
		return nil, err
	}

	key, err := certcrypto.ParsePEMPrivateKey(account.KeyData)
	if err != nil {
		return nil, err
	}

	account.key = key

	return account, nil
}

func StoreAccount(file string, account *Account) error {
	data, err := json.Marshal(account)
	if err != nil {
		return err
	}
	return os.WriteFile(file, data, 0600)
}

func (a *Account) GetEmail() string {
	return a.Email
}

func (a *Account) GetRegistration() *registration.Resource {
	return a.Registration
}

func (a *Account) GetPrivateKey() crypto.PrivateKey {
	return a.key
}
