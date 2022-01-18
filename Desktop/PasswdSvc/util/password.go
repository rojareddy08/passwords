package util

import (
	"errors"
	"math/rand"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type PasswdConfig struct {
	HasCaps    bool
	HasSymbols bool
	HasNumbers bool
	Length     int
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func GenerateRandomPassword(passwdConfig PasswdConfig) (string, error) {
	rand.Seed(time.Now().UnixNano())

	//check the input length
	if passwdConfig.Length < 8 {
		return "", errors.New("Password length should be more than or equal to 8")
	}

	passwd := make([]byte, passwdConfig.Length)

	variations := 1
	if passwdConfig.HasCaps {
		variations++
	}
	if passwdConfig.HasNumbers {
		variations++
	}
	if passwdConfig.HasSymbols {
		variations++
	}

	r := passwdConfig.Length / variations

	var numCaps, numSymbols, numNumbers int //number of elements that we have to generate

	if passwdConfig.HasCaps {
		numCaps = rand.Intn(r) + 1
	}
	if passwdConfig.HasSymbols {
		numSymbols = rand.Intn(r) + 1
	}
	if passwdConfig.HasNumbers {
		numNumbers = rand.Intn(r) + 1
	}

	//fmt.Printf("numCaps:%d, numSymbols:%d, numNumbers:%d\n", numCaps, numSymbols, numNumbers)

	var smallCount, capsCount, numsCount, symbolsCount int //counts the elements that we have generated

	for i := 0; i < passwdConfig.Length; {
		t := rand.Intn(4) + 1
		//fmt.Println(t)

		switch t {
		case 1:
			//small letter
			if smallCount < r {
				passwd[i] = byte(rand.Intn(26) + 'a')
				smallCount++
			}
		case 2:
			//capital letter
			if capsCount < numCaps {
				passwd[i] = byte(rand.Intn(26) + 'A')
				capsCount++
			}
		case 3:
			//symbol
			permittedSymbols := []byte{'#', '!', '@', '$', '%', '&', '^', '*', '?', '~'}
			if symbolsCount < numSymbols {
				passwd[i] = permittedSymbols[rand.Intn(len(permittedSymbols))]
				symbolsCount++
			}
		case 4:
			//number
			if numsCount < numNumbers {
				nums := []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
				passwd[i] = nums[rand.Intn(10)]
				numsCount++
			}
		}

		if passwd[i] != 0 {
			i++
		}

		//fmt.Printf("capsCount: %d, symbolsCount: %d, numsCount: %d\n", capsCount, symbolsCount, numsCount)

		if capsCount == numCaps && symbolsCount == numSymbols && numsCount == numNumbers {
			break
		}
	}

	for i := 0; i < passwdConfig.Length; i++ {
		if passwd[i] == 0 {
			passwd[i] = byte(rand.Intn(26) + 'a')
		}
	}

	return string(passwd), nil

}
