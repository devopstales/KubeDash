package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
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
	kubeConfigEnvName     = "KUBECONFIG"
	kdloginTimeoutEnvName = "KDLOGIN_TIMEOUT"
	defaultKdloginWait    = 10 * time.Second
	AppVersion            = "4.1.1"
)

func defaultWaitTimeoutFromEnv() time.Duration {
	v := strings.TrimSpace(os.Getenv(kdloginTimeoutEnvName))
	if v == "" {
		return defaultKdloginWait
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return defaultKdloginWait
	}
	return d
}

func kdloginUsage(defWait time.Duration) func() {
	return func() {
		name := filepath.Base(os.Args[0])
		fmt.Fprintf(os.Stderr, "Usage: %s [options] <kubebase-url>\n\nOptions:\n", name)
		fmt.Fprintf(os.Stderr, "  -h, --help\n        show this help and exit\n")
		fmt.Fprintf(os.Stderr, "  -v, --version\n        print version and exit\n")
		fmt.Fprintf(os.Stderr, "  -u, --url string\n        KubeDash base URL (required with -c/--code)\n")
		fmt.Fprintf(os.Stderr, "  -p, --port int\n        local TCP port for HTTP callback (default 8080)\n")
		fmt.Fprintf(os.Stderr, "  -c, --code string\n        fetch kubeconfig using a one-time code from KubeDash\n")
		fmt.Fprintf(os.Stderr, "  -t, --timeout duration\n        max wait for kubeconfig callback (default %s); 0 waits until Ctrl+C; %s sets default when unset\n", defWait.String(), kdloginTimeoutEnvName)
		fmt.Fprintf(os.Stderr, "  --debug\n        enable debug logging\n")
	}
}

var debugMode bool

type RequestOIDC struct {
	UserName                 string  `json:"username"  validate:"required"`
	Context                  string  `json:"context"  validate:"required"`
	Server                   string  `json:"server"  validate:"required"`
	CertificateAuthorityData string  `json:"certificate-authority-data"  validate:"required"`
	ClientID                 string  `json:"client-id"  validate:"required"`
	IDToken                  string  `json:"id-token"  validate:"required"`
	RefreshToken             string  `json:"refresh-token"  validate:"required"`
	IdpIssuerURL             string  `json:"idp-issuer-url"  validate:"required"`
	IdpIssuerCAData          *string `json:"idp-certificate-authority-data" validate:"omitempty"`
	ClientSecret             string  `json:"client_secret" validate:"required"`
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
	defWait := defaultWaitTimeoutFromEnv()
	flag.Usage = kdloginUsage(defWait)

	var (
		help        bool
		showVersion bool
		listenPort  int
		code        string
		baseURL     string
		waitTimeout time.Duration
	)

	flag.BoolVar(&help, "h", false, "")
	flag.BoolVar(&help, "help", false, "")
	flag.BoolVar(&showVersion, "v", false, "")
	flag.BoolVar(&showVersion, "version", false, "")
	flag.IntVar(&listenPort, "port", 8080, "")
	flag.IntVar(&listenPort, "p", 8080, "")
	flag.StringVar(&code, "code", "", "")
	flag.StringVar(&code, "c", "", "")
	flag.StringVar(&baseURL, "base-url", "", "")
	flag.StringVar(&baseURL, "url", "", "")
	flag.StringVar(&baseURL, "u", "", "")
	flag.DurationVar(&waitTimeout, "timeout", defWait, "")
	flag.DurationVar(&waitTimeout, "t", defWait, "")
	flag.BoolVar(&debugMode, "debug", false, "")
	flag.Parse()

	if help {
		flag.Usage()
		os.Exit(0)
	}
	if showVersion {
		fmt.Println(AppVersion)
		os.Exit(0)
	}

	if code != "" {
		if strings.TrimSpace(baseURL) == "" {
			fmt.Fprintln(os.Stderr, "kdlogin: -u/--url is required when using -c/--code")
			os.Exit(2)
		}
		if err := fetchConfigByCode(strings.TrimRight(strings.TrimSpace(baseURL), "/"), strings.TrimSpace(code)); err != nil {
			log.Fatal(err)
		}
		return
	}

	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "kdlogin: expected exactly one kubebase-url argument")
		flag.Usage()
		os.Exit(2)
	}
	if !isValidUrl(args[0]) {
		fmt.Fprintln(os.Stderr, "kdlogin: argument is not a valid URL")
		flag.Usage()
		os.Exit(2)
	}
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Enable debug mode if the flag is set
	if debugMode {
		router.Use(gin.Logger())
	}

	// Browser handoff: HTTPS KubeDash page POSTs kubeconfig to http://<plugin-reported-host>:port/ (CORS).
	router.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type")
		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	})

	router.GET("/info", info)
	router.GET("/ping", ping)
	kubeconfigDone := make(chan struct{}, 1)
	router.POST("/", func(c *gin.Context) {
		callback(c, kubeconfigDone)
	})

	srv := &http.Server{
		Handler: router,
	}
	listenAddr := fmt.Sprintf("0.0.0.0:%d", listenPort)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen: %s\n", err)
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Fatalf("serve: %s\n", err)
		}
	}()

	// Open the browser only after the local listener is bound, so KubeDash can push
	// to kdlogin_client as soon as the OAuth callback runs (avoids ECONNREFUSED races).
	openURL := kdloginStartURL(args[0], listenPort)
	debug("Opening URL in browser:", openURL)
	OpenInBrowser(openURL)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)

	var timeoutCh <-chan time.Time
	if waitTimeout > 0 {
		timeoutCh = time.After(waitTimeout)
	}

	timedOut := false
	select {
	case <-quit:
	case <-timeoutCh:
		timedOut = true
		fmt.Fprintln(os.Stderr, "kdlogin: timed out waiting for kubeconfig callback (use --timeout/-t or "+kdloginTimeoutEnvName+" to increase; --timeout=0 waits indefinitely)")
	case <-kubeconfigDone:
		// Let the KubeDash HTTP client finish reading the 200 response before Shutdown.
		time.Sleep(200 * time.Millisecond)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("Server Shutdown:", err)
	}
	if timedOut {
		os.Exit(1)
	}
}

func info(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "kdlogin"})
}

func ping(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "pong", "service": "kdlogin"})
}

func isValidUrl(toTest string) bool {
	_, err := url.ParseRequestURI(toTest)
	if err != nil {
		return false
	}

	u, err := url.Parse(toTest)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// primaryHostIPv4 returns the first non-loopback, non-link-local IPv4 on local interfaces.
// Used so KubeDash can push kubeconfig to the machine running this binary (browser headers
// often only show the Docker gateway or 127.0.0.1 from the app server's perspective).
func primaryHostIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ipnet.IP.To4()
		if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
			continue
		}
		return v4.String()
	}
	return ""
}

// kdloginStartURL builds the KubeDash URL that starts the kdlogin OIDC flow.
// The server sets session (oidc_client_flow=kdlogin, optional port) only on GET /.../kdlogin.
// Opening only the site root leaves that unset, so the callback never POSTs kubeconfig to this process.
func kdloginStartURL(raw string, port int) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return raw
	}
	trimmed := strings.Trim(u.Path, "/")
	if trimmed == "kdlogin" || strings.HasSuffix(trimmed, "/kdlogin") {
		// already targeting kdlogin entry
	} else if trimmed == "" {
		u.Path = "/kdlogin"
	} else {
		u.Path = "/" + trimmed + "/kdlogin"
	}
	q := u.Query()
	if port != 8080 && q.Get("port") == "" {
		q.Set("port", fmt.Sprintf("%d", port))
	}
	if q.Get("kdlogin_client") == "" {
		if h := primaryHostIPv4(); h != "" {
			q.Set("kdlogin_client", h)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func fetchConfigByCode(baseURL, code string) error {
	u, err := url.Parse(baseURL)
	if err != nil {
		return err
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/api/v1/kdlogin/config"
	q := u.Query()
	q.Set("code", code)
	u.RawQuery = q.Encode()
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(u.String())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("kdlogin config: %s: %s", resp.Status, string(body))
	}
	var req RequestOIDC
	if err := json.NewDecoder(resp.Body).Decode(&req); err != nil {
		return err
	}
	validate := validator.New()
	if err := validate.Struct(req); err != nil {
		return fmt.Errorf("invalid config payload: %w", err)
	}
	requestConfig, ctx := createValidTestConfigOIDC(req)
	return mergeAndWriteKubeconfig(requestConfig, ctx)
}

func mergeAndWriteKubeconfig(requestConfig clientcmdapi.Config, context string) error {
	fileExist, kubeconfig := GetKubeConfig()
	debug("Kubeconfig file found:", fileExist, kubeconfig)

	configOverrides, err := ioutil.TempFile("", "kubeconfig-*")
	if err != nil {
		return err
	}
	defer os.Remove(configOverrides.Name())

	if err := clientcmd.WriteToFile(requestConfig, configOverrides.Name()); err != nil {
		return err
	}

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
		return err
	}

	enc, err := pkgruntime.Encode(clientcmdlatest.Codec, mergedConfig)
	if err != nil {
		return err
	}

	output, err := yaml.JSONToYAML(enc)
	if err != nil {
		return err
	}

	if err := WriteToFile(string(output), context); err != nil {
		return err
	}
	return nil
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

func callback(c *gin.Context, done chan<- struct{}) {
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

	if err := mergeAndWriteKubeconfig(requestConfig, context); err != nil {
		log.Fatalf("Unexpected error: %v", err)
	}
	// Explicit close so browser fetch() gets a complete response (HTTP/1.1 defaults to keep-alive).
	c.Header("Connection", "close")
	c.JSON(http.StatusOK, gin.H{"ok": true, "message": "kdlogin"})
	// Respond before exiting: WriteToFile used to os.Exit(0) before this line, so clients never
	// saw 200 and KubeDash fell back to browser handoff while the listener was already gone.
	if f, ok := c.Writer.(http.Flusher); ok {
		f.Flush()
	}
	select {
	case done <- struct{}{}:
	default:
	}
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
	caVal := ""
	if request.IdpIssuerCAData != nil {
		caVal = strings.TrimSpace(*request.IdpIssuerCAData)
	}
	if caVal != "" && caVal != "none" {
		authProviderConfig["idp-certificate-authority-data"] = caVal
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

func WriteToFile(content string, context string) error {
	homedir, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dirname := filepath.Join(homedir, ".kube")
	filename := filepath.Join(dirname, "config")

	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(content); err != nil {
		return err
	}

	log.Printf("Config file created for context [%s] at %s", context, filename)
	fmt.Println("Happy Kubernetes interaction!")
	return nil
}

func debug(args ...any) {
	if debugMode {
		log.Println("[DEBUG]", fmt.Sprint(args...))
	}
}
