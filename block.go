package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// Block represents a block in the blockchain.
type Block struct {
	ID           int
	Index        int
	Timestamp    time.Time
	Transactions []Transaction
	Hash         string
	PrevHash     string
	Nonce        string
	Difficulty   int
}

// Transaction represents a transaction in the blockchain.
type Transaction struct {
	ID        string
	Sender    string
	Recipient string
	Value     int
}

// Blockchain represents the blockchain.
var Blockchain []Block

// MiningReward represents the number of coins rewarded for mining a new block.
const MiningReward = 1

// Mutex for controlling concurrent access to the blockchain.
var mutex = &sync.Mutex{}

// generateBlock creates a new block in the blockchain.
func generateBlock(prevBlock Block, transactions []Transaction) (Block, error) {
	var newBlock Block

	t := time.Now()
	newBlock.Index = prevBlock.Index + 1
	newBlock.Timestamp = t
	newBlock.Transactions = transactions
	newBlock.PrevHash = prevBlock.Hash
	newBlock.Difficulty = 4 // Пример сложности работы: 4 ведущих нуля

	// Вычисление хэша блока и проверка сложности работы
	for i := 0; ; i++ {
		hex := fmt.Sprintf("%x", i)
		newBlock.Nonce = hex
		newBlock.Hash = calculateHash(newBlock)
		if isHashValid(newBlock.Hash, newBlock.Difficulty) {
			return newBlock, nil
		}
	}
}

// calculateHash calculates the hash of a block.
func calculateHash(block Block) string {
	record := strconv.Itoa(block.Index) + block.Timestamp.String() + fmt.Sprintf("%v", block.Transactions) + block.PrevHash + block.Nonce
	h := sha256.New()
	h.Write([]byte(record))
	hashed := h.Sum(nil)
	return hex.EncodeToString(hashed)
}

// isHashValid checks if the hash meets the required criteria.
func isHashValid(hash string, difficulty int) bool {
	prefix := strings.Repeat("0", difficulty)
	return strings.HasPrefix(hash, prefix)
}

// generateGenesisBlock creates the genesis block of the blockchain using Proof-of-Work.
func generateGenesisBlock(difficulty int) Block {
	var genesisBlock Block
	genesisBlock.Index = 0
	genesisBlock.Timestamp = time.Now()
	genesisBlock.Transactions = []Transaction{}
	genesisBlock.PrevHash = ""
	genesisBlock.Difficulty = difficulty
	genesisBlock.Hash = calculateProofOfWork(genesisBlock, difficulty)

	return genesisBlock
}

// calculateProofOfWork calculates the proof-of-work for a block.
func calculateProofOfWork(block Block, difficulty int) string {
	target := strings.Repeat("0", difficulty)
	for nonce := 0; ; nonce++ {
		hex := fmt.Sprintf("%x", nonce)
		block.Nonce = hex
		hash := calculateHash(block)
		if strings.HasPrefix(hash, target) {
			return hash
		}
	}
}

// initBlockchain initializes the blockchain with the genesis block.
func initBlockchain() {
	genesisBlock := generateGenesisBlock(4)
	spew.Dump(genesisBlock)
	mutex.Lock()
	Blockchain = append(Blockchain, genesisBlock)
	mutex.Unlock()
}

// addBlock добавляет новый блок в блокчейн и сохраняет его в базе данных.
func addBlock(newBlock Block, db *sql.DB) {
	mutex.Lock()
	Blockchain = append(Blockchain, newBlock)
	mutex.Unlock()
	spew.Dump(newBlock)

	// Преобразование идентификаторов транзакций в формат JSON
	transactionIDs := make([]string, len(newBlock.Transactions))
	for i, tx := range newBlock.Transactions {
		transactionIDs[i] = tx.ID
	}
	transactionIDsJSON, err := json.Marshal(transactionIDs)
	if err != nil {
		log.Println("Failed to marshal transaction IDs to JSON:", err)
		log.Println(err)
		return
	}

	// Вставка блока в таблицу blocks
	query := "INSERT INTO blocks (index, timestamp, transactions, hash, prev_hash, nonce, difficulty, transactions_id) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
	// Проверка на наличие транзакций
	var transactionsID interface{}
	if len(transactionIDs) > 0 {
		transactionsID = transactionIDsJSON
	} else {
		transactionsID = nil
	}
	if transactionsID == nil {
		_, err = db.Exec(query, newBlock.Index, newBlock.Timestamp, newBlock.TransactionsJSON(), newBlock.Hash, newBlock.PrevHash, newBlock.Nonce, newBlock.Difficulty, nil)
	} else {
		_, err = db.Exec(query, newBlock.Index, newBlock.Timestamp, newBlock.TransactionsJSON(), newBlock.Hash, newBlock.PrevHash, newBlock.Nonce, newBlock.Difficulty, transactionsID)
	}
	if err != nil {
		log.Println("Failed to insert block into database:", err)
	}
}

// TransactionsJSON возвращает JSON-представление транзакций.
func (block *Block) TransactionsJSON() []byte {
	transactionsJSON, err := json.Marshal(block.Transactions)
	if err != nil {
		log.Println("Failed to marshal transactions to JSON:", err)
		return []byte{}
	}
	return transactionsJSON
}

// Wallet represents a wallet.
type Wallet struct {
	ID            int
	PrivateKey    *rsa.PrivateKey
	PublicKey     *rsa.PublicKey
	Balance       int
	UniqueUserKey string
	Adress        string
}

// generateWallet creates a new wallet.
func generateWallet() (*Wallet, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %v", err)
	}

	publicKey := &privateKey.PublicKey
	wallet := &Wallet{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Balance:    0,
		Adress:     generateAddress(publicKey),
	}

	return wallet, nil
}

// savePrivateKeyToFile saves the private key to a file.
func savePrivateKeyToFile(filepath string, privateKey *rsa.PrivateKey) error {
	privateKeyPEM := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	privateKeyFile, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create private key file: %v", err)
	}
	defer privateKeyFile.Close()

	err = pem.Encode(privateKeyFile, privateKeyPEM)
	if err != nil {
		return fmt.Errorf("failed to write private key to file: %v", err)
	}

	return nil
}

// savePublicKeyToFile saves the public key to a file.
func savePublicKeyToFile(filepath string, publicKey *rsa.PublicKey) error {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}

	publicKeyFile, err := os.Create(filepath)
	if err != nil {
		return fmt.Errorf("failed to create public key file: %v", err)
	}
	defer publicKeyFile.Close()

	_, err = publicKeyFile.Write(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("failed to write public key to file: %v", err)
	}

	return nil
}

// saveWalletToDB saves the wallet to the database.
func saveWalletToDB(db *sql.DB, wallet *Wallet) error {
	query := "INSERT INTO wallets (private_key, public_key, balance, UniqueUserKey, adress) VALUES ($1, $2, $3, $4, $5) RETURNING id"
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(wallet.PrivateKey)
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(wallet.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal public key: %v", err)
	}
	err = db.QueryRow(query, privateKeyBytes, publicKeyBytes, wallet.Balance, wallet.UniqueUserKey, wallet.Adress).Scan(&wallet.ID)
	if err != nil {
		return fmt.Errorf("failed to insert wallet into database: %v", err)
	}
	return nil
}

// getWalletFromDB retrieves a wallet from the database by ID.
func getWalletFromDB(db *sql.DB, walletID int) (*Wallet, error) {
	query := "SELECT private_key, public_key, balance, UniqueUserKey, adress FROM wallets WHERE id = $1"
	var privateKeyBytes []byte
	var publicKeyBytes []byte
	var balance int
	var uniqueuserkey string
	var adress string
	err := db.QueryRow(query, walletID).Scan(&privateKeyBytes, &publicKeyBytes, &balance, &uniqueuserkey, &adress)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet from database: %v", err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	wallet := &Wallet{
		ID:            walletID,
		PrivateKey:    privateKey,
		PublicKey:     publicKey.(*rsa.PublicKey),
		Balance:       balance,
		UniqueUserKey: uniqueuserkey,
		Adress:        adress,
	}

	return wallet, nil
}

func getWalletWithUniqueUserKeyFromDB(db *sql.DB, UniqueUserKeyGet string) (*Wallet, error) {
	query := "SELECT private_key, public_key, balance, id, adress FROM wallets WHERE uniqueuserkey = $1"
	var privateKeyBytes []byte
	var publicKeyBytes []byte
	var balance int
	var id int
	var adress string
	err := db.QueryRow(query, UniqueUserKeyGet).Scan(&privateKeyBytes, &publicKeyBytes, &balance, &id, &adress)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet from database: %v", err)
		log.Println(err)
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
		log.Println(err)
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
		log.Println(err)
	}

	wallet := &Wallet{
		ID:            id,
		PrivateKey:    privateKey,
		PublicKey:     publicKey.(*rsa.PublicKey),
		Balance:       balance,
		UniqueUserKey: UniqueUserKeyGet,
		Adress:        adress,
	}

	return wallet, nil
}

// generateAddress generates an address based on the public key.
func generateAddress(publicKey *rsa.PublicKey) string {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(publicKeyBytes)
	return hex.EncodeToString(hash[:])
}

// sendCoins sends coins from the sender wallet to the recipient address.
func sendCoins(c *gin.Context, senderWallet *Wallet, recipientAddress string, amount int) error {

	if senderWallet.Balance < amount {
		return fmt.Errorf("insufficient funds")
	}

	senderAddress := generateAddress(senderWallet.PublicKey)

	tx := Transaction{
		ID:        uuid.New().String(),
		Sender:    senderAddress,
		Recipient: recipientAddress,
		Value:     amount,
	}

	newTransactions := []Transaction{tx}

	mutex.Lock()
	prevBlock := Blockchain[len(Blockchain)-1]
	mutex.Unlock()

	newBlock, err := generateBlock(prevBlock, newTransactions)
	if err != nil {
		return fmt.Errorf("failed to generate new block: %v", err)
	}

	mutex.Lock()
	Blockchain = append(Blockchain, newBlock)
	mutex.Unlock()

	senderWallet.Balance -= amount
	log.Println(recipientAddress)
	recipientWallet, err := getWalletWithAddressFromDB(c, recipientAddress)
	if err != nil {
		// Обработка ошибки, если кошелек получателя не найден
		return fmt.Errorf("recipient wallet not found: %v", err)
	}
	recipientWallet.Balance += amount

	// Сохранение обновленных балансов в базе данных или другом хранилище
	err = updateWalletBalancesInDB(c, senderWallet, recipientWallet)
	if err != nil {
		// Обработка ошибки сохранения обновленных балансов
		return fmt.Errorf("failed to update wallet balances: %v", err)
	}

	return nil
}

func updateWalletBalancesInDB(c *gin.Context, senderWallet *Wallet, recipientWallet *Wallet) error {
	db := c.MustGet("db").(*sql.DB)

	// Выполните соответствующий запрос к базе данных для обновления балансов
	query := "UPDATE wallets SET balance = $1 WHERE id = $2"
	_, err := db.Exec(query, senderWallet.Balance, senderWallet.ID)
	if err != nil {
		return fmt.Errorf("failed to update sender wallet balance in the database: %v", err)
	}

	query = "UPDATE wallets SET balance = $1 WHERE id = $2"
	_, err = db.Exec(query, recipientWallet.Balance, recipientWallet.ID)
	if err != nil {
		return fmt.Errorf("failed to update recipient wallet balance in the database: %v", err)
	}

	return nil
}

func getWalletWithAddressFromDB(c *gin.Context, address string) (*Wallet, error) {
	db := c.MustGet("db").(*sql.DB)

	// Выполните соответствующий запрос к базе данных для получения кошелька по адресу
	query := "SELECT id, balance FROM wallets WHERE adress = $1"
	row := db.QueryRow(query, address)

	wallet := &Wallet{}
	err := row.Scan(&wallet.ID, &wallet.Balance)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve wallet from the database: %v", err)
	}

	return wallet, nil
}

func GetGetUniqueUserKey(c *gin.Context) string {
	type WalletRequest struct {
		UniqueUserKey string `json:"uniqueUserKey"`
	}
	var walletRequest WalletRequest
	if err := c.ShouldBindJSON(&walletRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return "error"
	}
	uniqueUserKey := walletRequest.UniqueUserKey
	return uniqueUserKey
}

// handleNewWallet handles the creation of a new wallet.
func handleNewWallet(c *gin.Context) {
	db := c.MustGet("db").(*sql.DB)
	uniqueUserKey := GetGetUniqueUserKey(c)
	log.Println(uniqueUserKey)

	wallet, err := getWalletWithUniqueUserKeyFromDB(db, uniqueUserKey)
	if err == nil {
		addressex := generateAddress(wallet.PublicKey)
		// If the wallet already exists, return the corresponding response
		c.JSON(http.StatusOK, gin.H{
			"message":      "Wallet already exists",
			"wallet_id":    wallet.ID,
			"private_key":  wallet.PrivateKey,
			"public_key":   wallet.PublicKey,
			"initial_fund": wallet.Balance,
			"address":      addressex,
		})
		return
	}

	wallet, err = generateWallet()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}
	wallet.UniqueUserKey = uniqueUserKey

	err = saveWalletToDB(db, wallet)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	privateKeyFilePath := fmt.Sprintf("wallets/private_%d.pem", wallet.ID)
	err = savePrivateKeyToFile(privateKeyFilePath, wallet.PrivateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	publicKeyFilePath := fmt.Sprintf("wallets/public_%d.pem", wallet.ID)
	err = savePublicKeyToFile(publicKeyFilePath, wallet.PublicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	privateKeyContent, err := os.ReadFile(privateKeyFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	publicKeyContent, err := os.ReadFile(publicKeyFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	address := generateAddress(wallet.PublicKey)

	c.JSON(http.StatusOK, gin.H{
		"message":      "New wallet created",
		"wallet_id":    wallet.ID,
		"private_key":  privateKeyContent,
		"public_key":   publicKeyContent,
		"initial_fund": wallet.Balance,
		"address":      address,
	})
}

// handleSendCoins handles the sending of coins to another user.
func handleSendCoins(c *gin.Context) {
	db := c.MustGet("db").(*sql.DB)
	senderWalletID := c.Param("wallet_id")
	log.Println(senderWalletID)
	var recipient struct {
		Address string `json:"address"`
		Amount  int    `json:"amount"`
	}
	if err := c.ShouldBindJSON(&recipient); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	senderWallet, err := getWalletWithUniqueUserKeyFromDB(db, senderWalletID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	err = sendCoins(c, senderWallet, recipient.Address, recipient.Amount)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Coins sent successfully"})
}

// handleGetBalance handles the retrieval of wallet balance.
func handleGetBalance(c *gin.Context) {
	db := c.MustGet("db").(*sql.DB)
	walletID, err := strconv.Atoi(c.Param("wallet_id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid wallet ID"})
		return
	}

	wallet, err := getWalletFromDB(db, walletID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"balance": wallet.Balance})
}
func handleGetBalanceWithUserID(c *gin.Context) {
	db := c.MustGet("db").(*sql.DB)
	uniqueUserKey := c.Param("wallet_id")
	log.Println(uniqueUserKey)

	wallet, err := getWalletWithUniqueUserKeyFromDB(db, uniqueUserKey)
	if err != nil {
		// If the wallet is not found, return a specific response
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Wallet not found"})
			return
		}
		// If there is an internal server error, return an error response
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"balance": wallet.Balance})
}

func handleGetAdressWithUserID(c *gin.Context) {
	db := c.MustGet("db").(*sql.DB)
	uniqueUserKey := c.Param("wallet_id")
	log.Println(uniqueUserKey)

	wallet, err := getWalletWithUniqueUserKeyFromDB(db, uniqueUserKey)
	if err != nil {
		// If the wallet is not found, return a specific response
		if err == sql.ErrNoRows {
			c.JSON(http.StatusNotFound, gin.H{"error": "Wallet not found"})
			return
		}
		// If there is an internal server error, return an error response
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"adress": generateAddress(wallet.PublicKey)})
}

// handleGetBlockchain handles the retrieval of the blockchain.
func handleGetBlockchain(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"blockchain": Blockchain})

}

// handleMining handles the mining of a new block.
func handleMining(c *gin.Context) {
	db := c.MustGet("db").(*sql.DB)
	walletID := c.Param("wallet_id")
	wallet, err := getWalletWithUniqueUserKeyFromDB(db, walletID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	mutex.Lock()
	prevBlock := Blockchain[len(Blockchain)-1]
	mutex.Unlock()

	// Mine a new block
	newTransactions := []Transaction{}
	newBlock, err := generateBlock(prevBlock, newTransactions)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		log.Println(err)
		return
	}

	// Add the block to the blockchain and save it to the database
	addBlock(newBlock, db)

	// Increase the wallet balance by the mining reward
	wallet.Balance += MiningReward
	query := "UPDATE wallets SET balance = $1 WHERE UniqueUserKey = $2"
	_, err = db.Exec(query, wallet.Balance, walletID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update wallet balance"})
		log.Println(err)
		return
	}
	address := generateAddress(wallet.PublicKey)

	c.JSON(http.StatusOK, gin.H{"message": "Mining successful", "reward": MiningReward, "address": address})
}

func main() {
	initBlockchain()

	// Connect to the PostgreSQL database
	db, err := sql.Open("postgres", "host=localhost port=5432 user=postgres password=89818286905Niki dbname=postgres sslmode=disable")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	router := gin.Default()
	router.Use(func(c *gin.Context) {
		c.Set("db", db)
		c.Next()
	})

	router.POST("/wallets", handleNewWallet)
	router.POST("/wallets/:wallet_id/send-coins", handleSendCoins)
	router.GET("/wallets/:wallet_id/balance", handleGetBalance)
	router.GET("/blockchain", handleGetBlockchain)
	router.POST("/wallets/:wallet_id/mine", handleMining)
	router.GET("/wallets/:wallet_id/myBalance", handleGetBalanceWithUserID)
	router.GET("/wallets/:wallet_id/myAdress", handleGetAdressWithUserID)
	log.Fatal(router.Run("192.168.0.103:8081"))
}
