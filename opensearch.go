package opensearch

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"text/template"
	"time"

	"github.com/Delta456/box-cli-maker/v2"
	opensearch "github.com/opensearch-project/opensearch-go/v2"
	opensearchapi "github.com/opensearch-project/opensearch-go/v2/opensearchapi"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

type OpensearchResult struct {
	Took     int  `json:"took"`
	TimedOut bool `json:"timed_out"`
	Shards   struct {
		Total      int `json:"total"`
		Successful int `json:"successful"`
		Skipped    int `json:"skipped"`
		Failed     int `json:"failed"`
	} `json:"_shards"`
	Hits struct {
		Total struct {
			Value    int    `json:"value"`
			Relation string `json:"relation"`
		} `json:"total"`
		MaxScore float64 `json:"max_score"`
		Hits     []struct {
			Index  string  `json:"_index"`
			ID     string  `json:"_id"`
			Score  float64 `json:"_score"`
			Source struct {
				Host          string    `json:"host"`
				Ident         string    `json:"ident"`
				Flty          string    `json:"facility"`
				Severity      string    `json:"severity"`
				Mnemonic      string    `json:"mnemonic"`
				Logflag       string    `json:"logflag"`
				Message       string    `json:"message"`
				Hosttimestamp string    `json:"hosttimestamp"`
				Timestamp     time.Time `json:"@timestamp"`
				Tag           string    `json:"tag"`
			} `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

const OpensearchTemplate = `{
	"size": {{.Size}},
	"query": {
	  "bool": {
		"must": {
	{{- if .TermHosts}}
		  "terms": {"host": {{ sliceMarshal .TermHosts}} }
	{{- else }}
		  "match_all": {}
	{{- end}}
		},
		"filter": [
	{{- if .TermMessage }}
	{"simple_query_string": {
		"query": "{{ .TermMessage }}",
		"fields": ["message"],
		"flags": "ALL"
	 }},
	{{- end}}
	{{- if .Minutes }}
		  {"range": {"@timestamp": {"gte": "now-{{ .Minutes }}m/m"}}}
	{{- end}}
	{{- if .Days }}
		  {"range": {"@timestamp": {"gte": "now-{{ .Days }}/d"}}}
	{{- end}}
	{{- if .DateBegin }}
          {"range": {"@timestamp": {"gte": "{{ .DateBegin }}", "lte": "{{ .DateEnd }}", "format": "{{ .DateFormat }}", "time_zone": "+03:00" }}}
	{{- end}}
		]
	  }
	 },
	 "sort": [
		{
		  "@timestamp": {
			"order": "{{ .Sort }}"
		  }
		}
	  ]
	}
	`

type SearchQuery struct {
	TermHosts   []string
	Size        string
	TermMessage string
	Days        string
	Minutes     string
	Test        []string
	Sort        string
	DateBegin   string
	DateEnd     string
	DateFormat  string
}

type ConfigHosts struct {
	Name     string
	Hostname string   `json:"hostname"`
	Groups   []string `json:"groups"`
	IPv4     string
}

type LogsIgnore struct {
	Name string
	Type string
	Msg  string
}

var tmp *template.Template

var IndexName = []string{"syslog-*"}

var URL = []string{"https://monweb01.msk.lukoil.net/os/"}

var tpl bytes.Buffer

var verbose = bool(false)
var cfgHosts []ConfigHosts
var cfgIgnoreMsg []LogsIgnore
var cfgApp map[string]string
var cfgHostNames map[string]ConfigHosts
var cfgHostIP map[string]ConfigHosts
var ipHosts []string
var selGroups []string
var selHosts []string
var cfgLogsIgnore map[string]LogsIgnore

const CfgPath = "$HOME/inventory"

func InitConfig() {
	// fmt.Println("==>>inside initConfig")
	cfgHostNames = make(map[string]ConfigHosts)
	cfgHostIP = make(map[string]ConfigHosts)
	selGroups = strings.Split("", ",")
	selHosts = strings.Split("srt-hlf11", ",")
	// log.Println("GROUPS: ", selGroups)
	// fmt.Println("GROUPS: ", selGroups)
	loadHostsInv()
	loadVariables()
	desc := false
	ign := false
	cfgApp["desc"] = "asc"
	cfgApp["ignorelogs"] = ""
	if ign {
		cfgApp["ignorelogs"] = "yes"
	}
	if desc {
		cfgApp["desc"] = "desc"
	}
	RunSearch()

}

func RunSearch() {
	if len(ipHosts) == 0 && viper.GetString("ipaddr") == "" {
		log.Fatal("Need to select hosts, options -i, -g, -a")
	}
	if viper.GetString("date") != "" && viper.GetString("time") != "" {
		log.Fatal("Need only one option: -t  or -d")
	}
	if viper.GetString("records") != "" {
		cfgApp["max_records"] = viper.GetString("records")
	}
	if verbose {
		fmt.Println("VAR: ", cfgApp)
	}
	qr := SearchQuery{}
	tr := viper.GetString("search")
	if len(ipHosts) > 0 {
		if verbose {
			fmt.Println("IP hosts:", ipHosts)
		}
	}
	tmp = template.Must(template.New("foo").Funcs(funcMap).Parse(OpensearchTemplate))
	if viper.GetString("ipaddr") != "" {
		qr.TermHosts = strings.Split(viper.GetString("ipaddr"), ",")
	} else {
		qr.TermHosts = ipHosts
	}
	if tr != "" {
		qr.TermMessage = tr
	}
	if viper.GetString("date") != "" {
		dtBegEnd := strings.Split(viper.GetString("date"), ",")
		qr.DateBegin = dtBegEnd[0]
		if len(dtBegEnd) > 1 {
			qr.DateEnd = dtBegEnd[1]
		} else {
			qr.DateEnd = dtBegEnd[0]
		}
		if checkRegex(":", qr.DateBegin) {
			if len(strings.Split(qr.DateBegin, ":")) > 2 {
				qr.DateFormat = "dd/MM/yyyy:HH:mm"
			} else {
				qr.DateFormat = "dd/MM/yyyy:HH"
			}
		} else {
			qr.DateFormat = "dd/MM/yyyy"
		}
	}
	qr.Sort = cfgApp["desc"]
	if checkRegex("d", viper.GetString("time")) {
		qr.Days = viper.GetString("time")
	} else {
		qr.Minutes = viper.GetString("time")
	}
	qr.Size = cfgApp["max_records"]

	if verbose {
		fmt.Printf("QR: %+v\n", qr)
	}
	err := tmp.Execute(&tpl, qr)
	if err != nil {
		log.Fatalln(err)
	}
	if verbose {
		fmt.Println("QUERY: ", tpl.String())
	}
	getOpenSearch(tpl.String())

}

func sliceMarshal(x []string) string {
	j, _ := json.Marshal(x)
	return string(j)

}

var funcMap = template.FuncMap{
	"sliceMarshal": sliceMarshal,
}

func getSizeTerminal() int {
	width, _, err := term.GetSize(0)
	if err != nil {
		// fmt.Println("Terminal size is empty")
		width, _ = strconv.Atoi(cfgApp["terminal_width"])
	}
	return width

}

func getOpenSearch(templ string) {
	var pwd string
	pwd, exists := os.LookupEnv("DOM_PASSW")
	if !exists {
		fmt.Printf("Enter Password: ")
		pwds, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			fmt.Println("error get password: ", err.Error())
		}
		pwd = string(pwds)
		fmt.Printf("\n\n")
	}

	client, err := opensearch.NewClient(opensearch.Config{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Addresses: URL,
		Username:  cfgApp["dom_user"],
		Password:  pwd,
	})
	if err != nil {
		log.Fatalln(err.Error())
	}
	ctx := context.Background()
	content := strings.NewReader(templ)

	// fmt.Println(templ)

	search := opensearchapi.SearchRequest{
		Body:  content,
		Index: IndexName,
	}
	// var mres MyRespond
	mres, err := search.Do(ctx, client)
	if err != nil {
		log.Fatalln("search problem: ", err.Error())
	}
	defer mres.Body.Close()
	body, _ := io.ReadAll(mres.Body)
	// js := string(body)
	// fmt.Println(string(body))
	var dt OpensearchResult
	if err := json.Unmarshal(body, &dt); err != nil {
		panic(err)
	}
	// fmt.Println(dt)
	msgByHost := make(map[string][]string)
	for _, v := range dt.Hits.Hits {
		hstName := cfgHostIP[v.Source.Host].Name
		hstTimeStamp := strings.Split(v.Source.Hosttimestamp, ".")[0]
		sMsg := fmt.Sprintf("%s\n", v.Source.Message)
		flgMsgAdd := true
		//flgIgnoreName := false
		//flgIgnoreType := false
		//flgIgnoreMsg := false
		var cntNull = 0
		var cntTrue = 0
		//fmt.Println("=============================================================")
		//fmt.Println(v.Source.Message)
		for _, li := range cfgIgnoreMsg {
			cntNull = 0
			cntTrue = 0
			if li.Name != "" {
				//fmt.Println("Name OK!!!!!")
				cntNull += 1
			}
			if li.Type != "" {
				//fmt.Println("Type OK!!!!!")
				cntNull += 1
			}
			if li.Msg != "" {
				//fmt.Println("MSG OK!!!!!")
				cntNull += 1
			}

			if li.Name != "" && strings.Contains(strings.ToLower(v.Source.Flty), strings.ToLower(strings.TrimSpace(li.Name))) {
				//fmt.Println("Content Name OK!!!!!")
				cntTrue += 1
			}
			if li.Type != "" && strings.Contains(strings.ToLower(v.Source.Mnemonic), strings.ToLower(strings.TrimSpace(li.Type))) {
				//fmt.Println("Content Type OK!!!!!\n")
				cntTrue += 1
			}

			if li.Msg != "" && strings.Contains(strings.ToLower(v.Source.Message), strings.ToLower(strings.TrimSpace(li.Msg))) {
				//fmt.Println("Content MSG OK!!!!!")
				cntTrue += 1
			}
			if cntNull == cntTrue && cfgApp["ignorelogs"] == "yes" {
				//fmt.Println("Flag message false")
				flgMsgAdd = false
			}
			//fmt.Println(cntTrue, cntNull)

		}
		if hstTimeStamp != "" {
			//fmt.Printf("Time: %s %s\n", v.Source.Flty, v.Source.Mnemonic)
			// sMsg := fmt.Sprintf("%-20s %-10s %-s\n", strings.Replace(hstTimeStamp, "T", " ", 1), v.Source.Flty, strings.Split(v.Source.Message, ";")[1])
			if strings.Contains(v.Source.Message, "CID=0x") {
				sMsg = fmt.Sprintf("\033[91m%-20s %-10s %-20s\033[0m\n%-s\n", strings.Replace(hstTimeStamp, "T", " ", 1), v.Source.Flty, v.Source.Mnemonic, strings.Split(v.Source.Message, ";")[1])
			} else {
				sMsg = fmt.Sprintf("\033[91m%-20s %-10s %-20s\033[0m\n%-s\n", strings.Replace(hstTimeStamp, "T", " ", 1), v.Source.Flty, v.Source.Mnemonic, v.Source.Message)
			}
		}
		if flgMsgAdd {
			msgByHost[hstName] = append(msgByHost[hstName], sMsg)
		}

		// msgByHost[hstName] = append(msgByHost[hstName], strings.Replace(hstTimeStamp, "T", " ", 1)+" "+v.Source.Message)
		// fmt.Printf("%-20s %-10s %-s\n", strings.Replace(hstTimeStamp, "T", " ", 1), v.Source.Flty, strings.Split(v.Source.Message, ";")[1])
	}
	if err != nil {
		return
	}
	msgByHost = addEmoji(msgByHost)
	for key, val := range msgByHost {
		bx := box.New(box.Config{Px: 2, Py: 1, Type: "Single", Color: "Cyan", ContentAlign: "Left", TitlePos: "Top", AllowWrapping: true, WrappingLimit: getSizeTerminal() - 10})
		bx.Print(key, strings.Join(val, "\n"))

		// fmt.Printf("==================== %s ======================\n", key)
		// fmt.Println(strings.Join(val, "\n"))
	}
	fmt.Printf("Total found records: %d, Max cfg records: %s\n\n", dt.Hits.Total.Value, cfgApp["max_records"])
	// Box := box.New(box.Config{Px: 2, Py: 5, Type: "Single", Color: "Cyan"})
	// Box.Print("Box CLI Maker", "Highly Customized Terminal Box Maker")
	// Box := box.New(box.Config{Px: 2, Py: 1, Type: "Single", Color: "Cyan", ContentAlign: "Center"})
	// Box.Print("\033[1mBold\033[0m, works", "Btw \033[1mit works here too\033[0m, very nice")

}

func checkRegex(r string, s string) bool {
	matched, _ := regexp.MatchString(r, s)
	return matched
}

func addEmoji(lg map[string][]string) map[string][]string {
	emoji := map[string]string{
		"ssh":     "🤿",
		"down":    "👎",
		"up":      "👍",
		"ntp":     "🕘",
		"signal":  "📶",
		"default": "🤷",
		"ospf":    "🐥",
		"bgp":     "🦉",
		"conf":    "🙏",
	}
	// emoji_ssh := "🤷‍♂🖥🤿🥷👓"
	// emoji_l2vpn := "🦘"
	// emoji_mpls := "🪱"
	// emoji_env := "⛈"
	// // # emoji_config = "🏋" 🕘 ☢️ ☢️ 🌍
	lg_emoji := make(map[string][]string)
	// _, err := regexp.Compile(`+++`)
	for i, val := range lg {
		// fmt.Println("val: ", val)
		for _, j := range val {
			emoji_line := ""
			// fmt.Println("string: ", j)
			// matched, _ := regexp.MatchString(`(?i)ssh`, s)
			if checkRegex(`(?i)\sdown`, j) {
				emoji_line = emoji_line + emoji["down"]
			}
			if checkRegex(`(?i)\sup`, j) {
				emoji_line = emoji_line + emoji["up"]
			}
			if checkRegex(`(?i)ssh`, j) {
				emoji_line = emoji_line + emoji["ssh"]
			}
			if checkRegex(`(?i)bgp`, j) {
				emoji_line = emoji_line + emoji["bgp"]
			}
			if checkRegex(`(?i)ntp`, j) {
				emoji_line = emoji_line + emoji["ntp"]
			}
			if checkRegex(`(?i)commit|config_i`, j) {
				emoji_line = emoji_line + emoji["conf"]
			}
			if checkRegex(`(?i)low_rx_power|signal`, j) {
				emoji_line = emoji_line + emoji["signal"]
			}
			// fmt.Println(emoji_down, reflect.TypeOf(emoji_down))
			if emoji_line == "" {
				emoji_line = emoji_line + emoji["default"]
			}
			lg_emoji[i] = append(lg_emoji[i], fmt.Sprintf("%-2s %-s", emoji_line, j))
			// yellow := color.New(color.FgYellow).SprintFunc()
			// lg_emoji[i] = append(lg_emoji[i], fmt.Sprintf("%-3s %-s", emoji_line, yellow(j)))
		}
	}
	// fmt.Println(lg_emoji)
	return lg_emoji
	// matched, _ := regexp.MatchString(`ayayay`, "o no") // пустой «приемник» ошибки, ведь мы уверены, что пример отработает нормально
	// fmt.Println(matched) // false
}

func resolveHost(s string) string {
	ipv4, err := net.ResolveIPAddr("ip4", s)
	if err != nil {
		fmt.Println("Error to resolve name:", err.Error())
		return ""
	} else {
		return ipv4.String()
	}
	// fmt.Println(ipv4.String())
}

func loadVariables() {
	cfgApp = make(map[string]string)
	homeDir, err := os.UserHomeDir()
	cobra.CheckErr(err)
	// cfgPath, err := filepath.Abs(homeDir + "/inventory/")
	cfgPath := filepath.Join(homeDir, "/inventory/")
	if verbose {
		fmt.Println("PATHCFG: ", cfgPath)
	}

	// if err != nil {
	// 	fmt.Println("Problem with path", err.Error())
	// }
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		log.Fatalln("Path does not exist: ", cfgPath)
	}
	viper.SetConfigName("lukcli-go")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(cfgPath)
	err = viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	cfgApp["url"] = viper.GetString("url")
	cfgApp["dom_user"] = viper.GetString("dom_user")
	cfgApp["terminal_width"] = viper.GetString("terminal_width")
	cfgApp["max_records"] = viper.GetString("max_records")
	//cfgApp["imsg"] = viper.Get("imsg").([]interface{})
	//fmt.Printf("%s", cfgPath["imsg"])
	//theMessage := viper.Get("paths").([]interface{})
	//for _, mon := range theMessage {
	//	d := mon.(map[interface{}]interface{})
	//	fmt.Println(d[string("path")])
	//}
	viper.SetConfigName("logignore_lukcli")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(cfgPath)
	err = viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	//var imsg []LogsIgnore
	viper.UnmarshalKey("imsg", &cfgIgnoreMsg)
	//fmt.Println(imsg)
	//cfgApp["imsg"] = imsg
	//for _, v := range cfgIgnoreMsg {
	//	fmt.Println(v.Name)
	//	if v.Type == "" {
	//		fmt.Println("OOOOOOOOOOOOOO")
	//	}
	//	fmt.Println(v.Type)
	//}
}

func loadHostsInv() {
	homeDir, _ := os.UserHomeDir()
	// fmt.Println(homeDir)
	cfgPath, err := filepath.Abs(homeDir + "/inventory/")
	if err != nil {
		fmt.Println("Problem with path", err.Error())
	}
	// fmt.Println(cfgPath)
	if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
		log.Fatalln("Path does not exist: ", cfgPath)
	}
	viper.SetConfigName("hosts")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(cfgPath)
	err = viper.ReadInConfig()
	if err != nil {
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	for i, v := range viper.AllSettings() {
		// fmt.Println(i, v)
		jsonData, _ := json.Marshal(v)
		var structData ConfigHosts
		json.Unmarshal(jsonData, &structData)
		structData.Name = i
		if searchGroup(structData, selGroups) || searchHosts(i, selHosts) {
			structData.IPv4 = resolveHost(structData.Hostname)
			ipHosts = append(ipHosts, structData.IPv4)
			cfgHosts = append(cfgHosts, structData)
			cfgHostNames[i] = structData
			cfgHostIP[structData.IPv4] = structData
		}
		// ConfigHosts{structData.Name, structData.Hostname, structData.Groups}

	}
	//fmt.Println(cfgHostNames)
	// fmt.Println(cfgHostIP)
	// fmt.Println(ipHosts)

}

func searchGroup(dt ConfigHosts, key []string) bool {
	ret := false
	for _, element := range dt.Groups {
		for _, grp := range key {
			if element == grp {
				ret = true
			}
		}
	}
	return ret
}

func searchHosts(s string, key []string) bool {
	ret := false
	for _, hst := range key {
		if s == hst {
			ret = true
		}
	}
	return ret
}
