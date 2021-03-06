package logger

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

const (
	DefaultLogLevel = "debug"
	DefaultLogPath  = "/var/log/watch-dog/watch-dog.log"
)

var l *zap.Logger

func InitLogger(logPath, logLevel string) {
	if len(logPath) <= 0 {
		logPath = DefaultLogPath
	}
	if len(logLevel) <= 0 {
		logLevel = DefaultLogLevel
	}
	hook := lumberjack.Logger{
		Filename:   logPath,
		MaxSize:    1024,
		MaxBackups: 3,
		MaxAge:     7,
		Compress:   true,
	}
	w := zapcore.AddSync(&hook)

	var level zapcore.Level
	switch logLevel {
	case "debug":
		level = zap.DebugLevel
	case "info":
		level = zap.InfoLevel
	case "error":
		level = zap.ErrorLevel
	default:
		level = zap.DebugLevel
	}

	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	core := zapcore.NewCore(
		zapcore.NewConsoleEncoder(encoderConfig),
		w,
		level,
	)

	l = zap.New(core)
}

func GetLogger() *zap.Logger {
	return l
}
