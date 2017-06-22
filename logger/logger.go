package logger

import (
	"github.com/Sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"io"
	"os"
)

var logger = logrus.New()

func init() {
	logger.Out = os.Stdout
	logger.Level = logrus.InfoLevel
	logger.Formatter = new(prefixed.TextFormatter)
}

func SetOut(out io.Writer) {
	logger.Out = out
}

func SetLevel(level string) error {
	l, err := logrus.ParseLevel(level)
	if err != nil {
		return err
	}
	logger.Level = l
	return nil
}

func isDebugEnabled() bool {
	return logger.Level == logrus.DebugLevel
}

func Debug(format string, args ...interface{}) {
	logger.Debugf(format, args...)
}

func Error(format string, args ...interface{}) {
	logger.Errorf(format, args...)
}

func Warn(format string, args ...interface{}) {
	logger.Warnf(format, args...)
}

func isInfoEnabled() bool {
	return logger.Level == logrus.InfoLevel
}

func Info(format string, args ...interface{}) {
	logger.Infof(format, args...)
}
