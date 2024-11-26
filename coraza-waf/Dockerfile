FROM golang:1.22

WORKDIR /app

# Copiar arquivos de definição de módulos primeiro
COPY go.mod go.sum ./

# Baixar dependências
RUN go mod tidy

# Copiar o restante dos arquivos do projeto
COPY . .

# Compilar o código
RUN go build -o coraza-waf .

# Expor a porta usada pelo WAF
EXPOSE 8090

# Comando para iniciar o WAF
CMD ["./coraza-waf"]