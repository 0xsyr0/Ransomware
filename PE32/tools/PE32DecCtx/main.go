package main


import (
  "os"
  "fmt"
  "errors"
  "encoding/pem"
  "path/filepath"
  "crypto/x509"
  "crypto/rand"
  "crypto/sha512"
  "crypto/rsa"
  "crypto/mlkem"
)


const (
  RSAPrivKeyFileName = "rsa_privkey.txt"
  Kyber1024SeedFileName = "kyber1024_seed.bin"
)

var (
  // Invalid RSA private key
  ErrInvalidRSAPrivKey = errors.New("invalid RSA private key data")
)


// Main
func main() {

  if (len(os.Args) != 2) {
    appName := filepath.Base(os.Args[0])
    fmt.Printf("\nUsage: %s context.pe32c\n", appName)
    os.Exit(0)
  }

  fileName := os.Args[1]

  // Read RSA private key PEM data
  rsaPrivKeyPEMData, err := readFileData(RSAPrivKeyFileName, 0)
  if err != nil {
    fmt.Printf("Error: Failed to read RSA private key from '%s'\n",
               RSAPrivKeyFileName)
    os.Exit(1)
  }

  // Import RSA private key from PEM data
  rsaPrivKey, err := importRSAPrivateKeyFromPEM(rsaPrivKeyPEMData)
  if err != nil {
    fmt.Printf("Error: Unable to import RSA private key (%s)\n", err.Error())
    os.Exit(1)
  }

  fmt.Printf("RSA private key: OK (%d)\n", rsaPrivKey.Size() * 8)

  // Read Kyber1024 seed
  kyber1024Seed, err := readFileData(Kyber1024SeedFileName, mlkem.SeedSize)
  if err != nil {
    fmt.Printf("Error: Failed to read Kyber1024 seed from '%s'\n",
               Kyber1024SeedFileName)
    os.Exit(1)
  }

  kyber1024DecKey, err := mlkem.NewDecapsulationKey1024(kyber1024Seed)
  if err != nil {
    fmt.Printf("Error: Failed to expand Kyber1024 decapsulation key (%s)\n",
               err.Error())
    os.Exit(1)
  }

  fmt.Println("Kyber1024 decapsulation key: OK")

  // Read context data
  ctxData, err := readFileData(fileName, 0)
  if err != nil {
    fmt.Printf("Error: Failed to read context from '%s'\n", fileName)
    os.Exit(1)
  }

  ctxEntrySize := mlkem.CiphertextSize1024 + rsaPrivKey.Size()
  ctxNumEntries := len(ctxData) / ctxEntrySize

  fmt.Printf("Context entry size: %d\n", ctxEntrySize)
  fmt.Printf("Context size: %d\n", len(ctxData))
  fmt.Printf("Context entries: %d\n", ctxNumEntries)

  var keyData []byte

  hash := sha512.New()
  rng := rand.Reader

  for i := 0; i < ctxNumEntries; i++ {

    entryPos := i * ctxEntrySize
    encKey := ctxData[entryPos : entryPos + mlkem.CiphertextSize1024]
    encNonceData := ctxData[entryPos + mlkem.CiphertextSize1024:
                            entryPos + ctxEntrySize]

    // Decapsulate shared key (Kyber1024)
    key, err := kyber1024DecKey.Decapsulate(encKey)
    if err != nil {
      fmt.Printf("Error: Kyber1024 key decapsulation failed on entry %d\n", i)
      break
    }

    // Decrypt nonce data (RSA)
    nonceData, err := rsa.DecryptOAEP(hash, rng, rsaPrivKey, encNonceData,
                                      nil)
    if err != nil {
      fmt.Printf("Error: RSA decryption failed on entry %d\n", i)
      break
    }

    keyData = append(keyData, key...)
    keyData = append(keyData, nonceData...)
  }

  if len(keyData) == 0 {
    os.Exit(1)
  }

  fmt.Printf("Key data size: %d\n", len(keyData))

  // Save key data
  destFileName := fileName + ".dec"
  err = writeDataToFile(destFileName, keyData)
  if err != nil {
    fmt.Printf("Error: Couldn't save key data to '%s'\n", destFileName)
    os.Exit(1)
  }
}


// Import RSA private key from PEM data
func importRSAPrivateKeyFromPEM(rsaPrivKeyPEMData []byte) (*rsa.PrivateKey,
                                                           error) {

  block, _ := pem.Decode(rsaPrivKeyPEMData)
  if block == nil { return nil, ErrInvalidRSAPrivKey }

  key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
  if err != nil { return nil, err }

  switch key := key.(type) {
    case *rsa.PrivateKey:
      return key, nil
    default:
      return nil, ErrInvalidRSAPrivKey
  }
}


// Read data from file
func readFileData(filePath string, dataSize int) ([]byte, error) {

  f, err := os.Open(filePath)
  if err != nil { return nil, err }
  defer f.Close()

  if dataSize <= 0 {
    fileInfo, err := f.Stat()
    if err != nil { return nil, err }

    fileSize := fileInfo.Size()
    dataSize = int(fileSize)
  }

  buf := make([]byte, dataSize)

  bytesRead, err := f.Read(buf)
  if err != nil { return nil, err }
  return buf[:bytesRead], nil
}


// Write data to file
func writeDataToFile(fileName string, data []byte) error {

  f, err := os.Create(fileName)
  if err != nil { return err }
  defer f.Close()

  _, err = f.Write(data)
  if err != nil { return err }

  return nil
}
