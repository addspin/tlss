package utils

import (
	"strconv"
)

type TestDataInterface interface {
	TestInt(data string) (int, error)
	TestBool(data string) (bool, error)
}
type testData struct{}

// проверяем на ошибки конвертацию строки в число
func (t *testData) TestInt(data string) (int, error) {
	convData, err := strconv.Atoi(data)
	if err != nil {
		return 0, err
	}
	return convData, nil
}

// проверяем на ошибки конвертацию строки в bool
func (t *testData) TestBool(data string) (bool, error) {
	convData, err := strconv.ParseBool(data)
	if err != nil {
		return false, err
	}
	return convData, nil
}

func NewTestData() TestDataInterface {
	return &testData{}
}
