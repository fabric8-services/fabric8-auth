package account

import (
	"fmt"
	"strings"
)

// GenerateFullName generates the full name out of first name, middle name and last name.
func GenerateFullName(nameComponents ...*string) string {
	fullName := ""
	for _, n := range nameComponents {
		if n != nil {
			if len(fullName) == 0 {
				fullName = fmt.Sprintf("%s", *n)
			} else {
				fullName = fmt.Sprintf("%s %s", fullName, *n)
			}
		}
	}
	return fullName
}

// SplitFullName splits a name and returns the firstname, lastname
func SplitFullName(fullName string) (string, string) {
	nameComponents := strings.Split(fullName, " ")
	firstName := nameComponents[0]
	lastName := ""
	if len(nameComponents) > 1 {
		lastName = strings.Join(nameComponents[1:], " ")
	}
	return firstName, lastName
}
