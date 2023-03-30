package common

import (
	"os"

	"go.uber.org/zap"
)

func initZapLogger() *zap.Logger {
	GSCAN_LOG_LEVEL := os.Getenv("GSCAN_LOG_LEVEL")
	switch GSCAN_LOG_LEVEL {
	case "development":
		logger, err := zap.NewProduction()
		if err != nil {
			panic(err)
		}
		return logger
	case "production":
		fallthrough
	default:
		logger, err := zap.NewDevelopment()
		if err != nil {
			panic(err)
		}
		return logger
	}
}

var logger *zap.Logger = initZapLogger()

func GetLogger() *zap.Logger {
	return logger
}
