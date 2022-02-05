package cmd

import (
	"fmt"
	"os"
	"sync"
	"tomato.com/watch-dog/internal/neo4j"

	"tomato.com/watch-dog/pkg/logger"
	"tomato.com/watch-dog/pkg/option"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	doOnce  sync.Once
)

var rootCmd = &cobra.Command{
	Use:   "watch-dog",
	Short: "collect",
	Long:  `A collect like a hub of agents that run on every machine`,
	Run: func(cmd *cobra.Command, args []string) {
		logger.GetLogger().Info("start")
		run()
		interrupt := stop()
		<-interrupt
	},
}

func init() {
	cobra.OnInitialize(initConfig)
	flags := rootCmd.PersistentFlags()
	flags.StringVar(&cfgFile, "config", "./watch-dog.yaml", "config file")
	flags.Parsed()
	viper.BindPFlags(flags)
}

// initDB
func initDB() error {
	neo4jConfig := viper.GetStringMapString(option.Neo4j)
	if err := neo4j.NewDriver(neo4jConfig["db-uri"], neo4jConfig["username"], neo4jConfig["password"]); err != nil {
		logger.GetLogger().Error(err.Error())
		return err
	}
	return nil
}

// initConfig initConfig
func initConfig() {
	if cfgFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfgFile)
	}

	viper.SetEnvPrefix("watch")
	//viper.SetConfigName(".watch-dog") // name of config file (without extension)
	//viper.AddConfigPath("$HOME")   // adding home directory as first search path
	viper.AutomaticEnv() // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		fmt.Println("Using config file:", viper.ConfigFileUsed())
	}

	initLogger()
	if err := initDB(); err != nil {
		fmt.Println(err.Error())
		os.Exit(1)
	}
}

func initLogger() {
	logger.InitLogger(viper.GetString(option.LogPath), viper.GetString(option.LogLevel))
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func run() {
	beforeCollect()
}
