package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/spf13/viper"

	"passwd-svc/config"

	"github.com/gin-contrib/logger"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"passwd-svc/util"
)

func main() {
	//Loading configuration
	config.LoadConfig()

	// Log as JSON instead of the default ASCII formatter.
	log.SetFormatter(&log.JSONFormatter{})

	// Output to stdout instead of the default stderr
	// Can be any io.Writer, see below for File example
	log.SetOutput(os.Stdout)

	// Only log the warning severity or above.
	log.SetLevel(log.Level(viper.GetInt("logging.level")))
	log.Debug("this is a test log")

	router := gin.New()

	// Add the logger middleware
	router.Use(logger.SetLogger())

	router.GET(
		"/ping",
		func(c *gin.Context) {
			log.Info("Received ping message")
			c.JSON(http.StatusOK, gin.H{
				"message": "pong",
			})
		},
	)

	router.POST(
		"/password/encrypt",
		func(c *gin.Context) {
			input := struct {
				Password string `json:"password"`
			}{}

			if err := c.BindJSON(&input); err != nil {
				log.Error("Error parsing json input while enrypting the password", err.Error())
				c.JSON(http.StatusBadRequest, gin.H{
					"status":             http.StatusBadRequest,
					"message":            "Error in request body",
					"encrypted_password": "",
				})
				return
			}

			encryptedPasswd, err := util.HashPassword(input.Password)
			if err != nil {
				log.Error("Error while enrypting the password", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{
					"status":             http.StatusInternalServerError,
					"message":            "Error while encrypting the password",
					"encrypted_password": "",
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"status":             http.StatusOK,
				"message":            "password encrypted successfully",
				"encrypted_password": encryptedPasswd,
			})

			log.Info("password encrypted successfully")
		},
	)

	router.POST(
		"/password/validate",
		func(c *gin.Context) {
			input := struct {
				Password       string `json:"password"`
				StoredPassword string `json:"stored_password"`
			}{}

			if err := c.BindJSON(&input); err != nil {
				log.Error("Error parsing json input while validating the password", err.Error())
				c.JSON(http.StatusBadRequest, gin.H{
					"status":   http.StatusBadRequest,
					"message":  "Error in request body",
					"is_valid": false,
				})
				return
			}

			isValid := util.CheckPasswordHash(input.Password, input.StoredPassword)

			c.JSON(http.StatusOK, gin.H{
				"status":   http.StatusOK,
				"message":  "password validated successfully",
				"is_valid": isValid,
			})

			log.Info("password validated successfully")

		},
	)

	router.POST(
		"/password/generate",
		func(c *gin.Context) {
			input := struct {
				HasCaps    bool `json:"has_caps"`
				HasNumbers bool `json:"has_numbers"`
				HasSymbols bool `json:"has_symbols"`
				Length     int  `json:"length"`
			}{}

			if err := c.BindJSON(&input); err != nil {
				log.Error("Error parsing json input while generating randompassword", err.Error())
				c.JSON(http.StatusBadRequest, gin.H{
					"status":          http.StatusBadRequest,
					"message":         "Error in request body",
					"random_password": "",
				})
				return
			}

			pc := util.PasswdConfig{}
			pc.HasCaps = input.HasCaps
			pc.HasNumbers = input.HasNumbers
			pc.HasSymbols = input.HasSymbols
			pc.Length = input.Length

			passwd, err := util.GenerateRandomPassword(pc)
			if err != nil {
				log.Error("Error while generating random password", err.Error())
				c.JSON(http.StatusInternalServerError, gin.H{
					"status":          http.StatusInternalServerError,
					"message":         "Error while generating random password",
					"random_password": "",
				})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"status":          http.StatusOK,
				"message":         "random encrypted generated",
				"random_password": passwd,
			})

		},
	)

	port := viper.GetInt("webserver.port")
	log.Info("Port", port, "Starting web server")
	router.Run(fmt.Sprintf(":%d", port))
}
