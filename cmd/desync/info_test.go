package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io/ioutil"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestInfoCommand(t *testing.T) {
	expectedOutput := []byte(`{
		"total": 161,
		"unique": 131,
		"in-store": 131,
		"in-seed": 0,
		"size": 2097152,
		"dedup-size-not-in-seed": 1114112,
		"chunk-size-min": 2048,
		"chunk-size-avg": 8192,
		"chunk-size-max": 32768
	}`)
	exp := make(map[string]interface{})
	err := json.Unmarshal(expectedOutput, &exp)
	require.NoError(t, err)

	cmd := newInfoCommand(context.Background())
	cmd.SetArgs([]string{"-s", "testdata/blob1.store", "testdata/blob1.caibx"})
	b := new(bytes.Buffer)

	// Redirect the command's output
	stdout = b
	cmd.SetOutput(ioutil.Discard)
	_, err = cmd.ExecuteC()
	require.NoError(t, err)

	// Decode the output and compare to what's expected
	got := make(map[string]interface{})
	err = json.Unmarshal(b.Bytes(), &got)
	require.NoError(t, err)
	require.Equal(t, exp, got)
}

func TestInfoCommandWithSeed(t *testing.T) {
	expectedOutput := []byte(`{
		"total": 161,
		"unique": 131,
		"in-store": 131,
		"in-seed": 124,
		"size": 2097152,
		"dedup-size-not-in-seed": 80029,
		"chunk-size-min": 2048,
		"chunk-size-avg": 8192,
		"chunk-size-max": 32768
	}`)
	exp := make(map[string]interface{})
	err := json.Unmarshal(expectedOutput, &exp)
	require.NoError(t, err)

	cmd := newInfoCommand(context.Background())
	cmd.SetArgs([]string{
		"-s", "testdata/blob1.store",
		"--seed", "testdata/blob2.caibx",
		"testdata/blob1.caibx",
	})
	b := new(bytes.Buffer)

	// Redirect the command's output
	stdout = b
	cmd.SetOutput(ioutil.Discard)
	_, err = cmd.ExecuteC()
	require.NoError(t, err)

	// Decode the output and compare to what's expected
	got := make(map[string]interface{})
	err = json.Unmarshal(b.Bytes(), &got)
	require.NoError(t, err)
	require.Equal(t, exp, got)
}
