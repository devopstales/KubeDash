package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	pkgruntime "k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"

	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	clientcmdlatest "k8s.io/client-go/tools/clientcmd/api/latest"
)

const (
	kubeConfigEnvName = "KUBECONFIG"
	AppVersion        = "3.1.1"
)

var debugMode bool

type RequestOIDC struct {
	UserName                 string `json:"username"  validate:"required"`
	Context                  string `json:"context"  validate:"required"`
	Server                   string `json:"server"  validate:"required"`
	CertificateAuthorityData string `json:"certificate-authority-data"  validate:"required"`
	ClientID                 string `json:"client-id"  validate:"required"`
	IDToken                  string `json:"id-token"  validate:"required"`
	RefreshToken             string `json:"refresh-token"  validate:"required"`
	IdpIssuerURL             string `json:"idp-issuer-url"  validate:"required"`
	IdpIssuerCAData          string `json:"idp-certificate-authority-data"  validate:"optional"`
	ClientSecret             string `json:"client_secret"  validate:"required"`
}

type RequestCert struct {
	UserName                 string `json:"username"  validate:"required"`
	Context                  string `json:"context"  validate:"required"`
	Server                   string `json:"server"  validate:"required"`
	CertificateAuthorityData string `json:"certificate-authority-data"  validate:"required"`
	ClientKeyData            string `json:"user-private-key"  validate:"required"`
	ClientCertificateData    string `json:"user-certificate"  validate:"required"`
}

func main() {
	version := flag.Bool("v", false, "prints current app version")
	flag.BoolVar(&debugMode, "debug", false, "enable debug logging")
	flag.Parse()

	if *version {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	args := flag.Args() // use parsed args, NOT os.Args manually
	if len(args) == 1 {
		if isValidUrl(args[0]) {
			debug("Opening URL in browser:", args[0])
			OpenInBrowser(args[0])
		} else {
			fmt.Println("Argument is not a valid URL")
			os.Exit(2)
		}
	} else {
		fmt.Println("Incorrect Number of Arguments Provided")
		os.Exit(2)
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Enable debug mode if the flag is set
	if debugMode {
		router.Use(gin.Logger())
	}

	router.GET("/info", info)
	router.POST("/", callback)

	srv := &http.Server{
		Addr:    ":8080",
		Handler: router,
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	quit := make(chan os.Signal)
	signal.Notify(quit, os.Interrupt)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}
}

func info(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "kdlogin"})
}

func isValidUrl(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}

	u, err := url.Parse(toTest)
	return err == nil && u.Scheme != "" && u.Host != ""
}

func OpenInBrowser(url string) {
	var err error
	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Fatal(err)
	}
}

func callback(c *gin.Context) {
	var requestOIDC RequestOIDC
	var requestCert RequestCert
	var requestConfig clientcmdapi.Config
	var context string

	validate := validator.New()

	if err := c.ShouldBindBodyWith(&requestOIDC, binding.JSON); err == nil {
		if err := validate.Struct(requestOIDC); err == nil {
			debug("Received valid OIDC configuration")
			requestConfig, context = createValidTestConfigOIDC(requestOIDC)
		}
	}

	if context == "" {
		if err := c.ShouldBindBodyWith(&requestCert, binding.JSON); err == nil {
			if err := validate.Struct(requestCert); err == nil {
				debug("Received valid certificate-based configuration")
				requestConfig, context = createValidTestConfigCert(requestCert)
			}
		}
	}

	if context == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input data"})
		return
	}

	fileExist, kubeconfig := GetKubeConfig()
	debug("Kubeconfig file found:", fileExist, kubeconfig)

	configOverrides, err := ioutil.TempFile("", "kubeconfig-*")
	if err != nil {
		log.Fatal(err)
	}
	defer os.Remove(configOverrides.Name())

	clientcmd.WriteToFile(requestConfig, configOverrides.Name())

	precedence := []string{}
	if fileExist {
		precedence = append(precedence, kubeconfig)
	}
	precedence = append(precedence, configOverrides.Name())

	loadingRules := clientcmd.ClientConfigLoadingRules{
		Precedence: precedence,
	}

	mergedConfig, err := loadingRules.Load()
	if err != nil {
		log.Fatalf("Unexpected error: %v", err)
	}

	json, err := pkgruntime.Encode(clientcmdlatest.Codec, mergedConfig)
	if err != nil {
		log.Fatalf("Unexpected error: %v", err)
	}

	output, err := yaml.JSONToYAML(json)
	if err != nil {
		log.Fatalf("Unexpected error: %v", err)
	}

	WriteToFile(string(output), context)
	c.JSON(200, "Client Get Data")
}

func GetKubeConfig() (bool, string) {
	ConfigFilename := os.Getenv(kubeConfigEnvName)
	if ConfigFilename == "" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			log.Fatal(err)
		}
		dirname := filepath.Join(homedir, ".kube")
		filename := filepath.Join(dirname, "config")

		if _, err := os.Stat(dirname); os.IsNotExist(err) {
			os.Mkdir(dirname, 0755)
			return false, filename
		}
		if _, err := os.Stat(filename); os.IsNotExist(err) {
			return false, filename
		}
		return true, filename
	}
	if _, err := os.Stat(ConfigFilename); os.IsNotExist(err) {
		return false, ConfigFilename
	}
	return true, ConfigFilename
}

func createValidTestConfigOIDC(request RequestOIDC) (clientcmdapi.Config, string) {
	authProviderConfig := map[string]string{
		"client-id":      request.ClientID,
		"client-secret":  request.ClientSecret,
		"id-token":       request.IDToken,
		"idp-issuer-url": request.IdpIssuerURL,
		"refresh-token":  request.RefreshToken,
	}
	if request.IdpIssuerCAData != "" && request.IdpIssuerCAData != "none" {
		authProviderConfig["idp-certificate-authority-data"] = request.IdpIssuerCAData
		debug("Included idp-certificate-authority-data")
	} else {
		debug("Skipping idp-certificate-authority-data")
	}

	kubeConfig := clientcmdapi.Config{
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			request.UserName: {
				AuthProvider: &clientcmdapi.AuthProviderConfig{
					Name:   "oidc",
					Config: authProviderConfig,
				},
			},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			request.Context: {
				Server:                   request.Server,
				CertificateAuthorityData: []byte(request.CertificateAuthorityData),
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			request.Context: {
				AuthInfo: request.UserName,
				Cluster:  request.Context,
			},
		},
	}
	return kubeConfig, request.Context
}

func createValidTestConfigCert(request RequestCert) (clientcmdapi.Config, string) {
	kubeConfig := clientcmdapi.Config{
		AuthInfos: map[string]*clientcmdapi.AuthInfo{
			request.UserName: {
				ClientCertificateData: []byte(request.ClientCertificateData),
				ClientKeyData:         []byte(request.ClientKeyData),
			},
		},
		Clusters: map[string]*clientcmdapi.Cluster{
			request.Context: {
				Server:                   request.Server,
				CertificateAuthorityData: []byte(request.CertificateAuthorityData),
			},
		},
		Contexts: map[string]*clientcmdapi.Context{
			request.Context: {
				AuthInfo: request.UserName,
				Cluster:  request.Context,
			},
		},
	}
	return kubeConfig, request.Context
}

func WriteToFile(content string, context string) {
	homedir, err := os.UserHomeDir()
	if err != nil {
		log.Fatal(err)
	}
	dirname := filepath.Join(homedir, ".kube")
	filename := filepath.Join(dirname, "config")

	f, err := os.Create(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		log.Fatal(err)
	}

	log.Printf("Config file created for context [%s] at %s", context, filename)
	fmt.Println("Happy Kubernetes interaction!")
	os.Exit(0)
}

func debug(args ...any) {
	if debugMode {
		log.Println("[DEBUG]", fmt.Sprint(args...))
	}
}
