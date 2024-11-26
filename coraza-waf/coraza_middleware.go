package main

import (
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"

	"github.com/corazawaf/coraza/v3"
	txhttp "github.com/corazawaf/coraza/v3/http"
	"github.com/corazawaf/coraza/v3/types"
)

func main() {
	waf := createWAF()

	// Define o URL de destino para o proxy
	targetURL, err := url.Parse("http://app:5002") // Use o nome do serviço definido no Docker Compose
	if err != nil {
		log.Fatal(err)
	}

	// Cria um Reverse Proxy para o URL de destino
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Opcional: Personaliza a função Director para preservar o Host original
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Preserva o header Host original
		req.Host = req.Header.Get("Host")
	}

	// Envolve o handler do proxy com o middleware do WAF
	http.Handle("/", txhttp.WrapHandler(waf, proxy))

	fmt.Println("Servidor WAF está executando na porta 8090")

	log.Fatal(http.ListenAndServe(":8090", nil))
}

func createWAF() coraza.WAF {
	// Ajuste o caminho do arquivo de configuração para corresponder à estrutura fornecida
	// directivesFile := "/coraza-waf/coraza-rules/crs-setup.conf" // Caminho absoluto para compatibilidade no container
	directivesFile := "/coraza-waf/coraza-rules/crs-setup.conf"
	if s := os.Getenv("DIRECTIVES_FILE"); s != "" {
		directivesFile = s
	}

	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithErrorCallback(logError).
			WithDirectivesFromFile(directivesFile),
	)
	if err != nil {
		log.Fatal(err)
	}
	return waf
}

func logError(error types.MatchedRule) {
	msg := error.ErrorLog()
	fmt.Printf("[logError][%s] %s\n", error.Rule().Severity(), msg)
}
