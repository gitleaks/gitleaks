package rules

// TODO introduce skiplists:
// https://github.com/danielmiessler/SecLists/blob/master/Miscellaneous/wordlist-skipfish.fuzz.txt
// https://github.com/e3b0c442/keywords
// https://gist.github.com/maxtruxa/b2ca551e42d3aead2b3d
// https://github.com/HChakraborty/projects/commit/e860cb863ee9585c38db8360814b04ef9fa1bdce
// https://github.com/UraniumX92/Discord-Bot-using-py/tree/224b2b71a58c25f420ce980f2ea49627b4b646f1/Data%20Files
// https://github.com/Meen11/BSBI-Indexing/blob/63032017aa24f3111f18468607cd0db5997bb891/datasets/citeseer/11/10.1.1.27.6385.txt

var DefaultStopWords = []string{
	"000000",
	"aaaaaa",
	"about",
	"abstract",
	"academy",
	"acces",
	"account",
	"act-",
	"act.",
	"act_",
	"action",
	"active",
	"actively",
	"activity",
	"adapter",
	"add-",
	"add.",
	"add_",
	"add-on",
	"addon",
	"addres",
	"admin",
	"adobe",
	"advanced",
	"adventure",
	"agent",
	"agile",
	"air-",
	"air.",
	"air_",
	"ajax",
	"akka",
	"alert",
	"alfred",
	"algorithm",
	"all-",
	"all.",
	"all_",
	"alloy",
	"alpha",
	"amazon",
	"amqp",
	"analysi",
	"analytic",
	"analyzer",
	"android",
	"angular",
	"angularj",
	"animate",
	"animation",
	"another",
	"ansible",
	"answer",
	"ant-",
	"ant.",
	"ant_",
	"any-",
	"any.",
	"any_",
	"apache",
	// "api-",
	// "api.",
	// "api_", lin_api_ is used for linear
	"app-",
	"app-",
	"app.",
	"app.",
	"app_",
	"app_",
	"apple",
	"arch",
	"archive",
	"archived",
	"arduino",
	"array",
	"art-",
	"art.",
	"art_",
	"article",
	"asp-",
	"asp.",
	"asp_",
	"asset",
	"async",
	"atom",
	"attention",
	"audio",
	"audit",
	"aura",
	"auth",
	"author",
	"author",
	"authorize",
	"auto",
	"automated",
	"automatic",
	"awesome",
	"aws_",
	"azure",
	"back",
	"backbone",
	"backend",
	"backup",
	"bar-",
	"bar.",
	"bar_",
	"base",
	"based",
	"bash",
	"basic",
	"batch",
	"been",
	"beer",
	"behavior",
	"being",
	"benchmark",
	"best",
	"beta",
	"better",
	"big-",
	"big.",
	"big_",
	"binary",
	"binding",
	"bit-",
	"bit.",
	"bit_",
	"bitcoin",
	"block",
	"blog",
	"board",
	"book",
	"bookmark",
	"boost",
	"boot",
	"bootstrap",
	"bosh",
	"bot-",
	"bot.",
	"bot_",
	"bower",
	"box-",
	"box.",
	"box_",
	"boxen",
	"bracket",
	"branch",
	"bridge",
	"browser",
	"brunch",
	"buffer",
	"bug-",
	"bug.",
	"bug_",
	"build",
	"builder",
	"building",
	"buildout",
	"buildpack",
	"built",
	"bundle",
	"busines",
	"but-",
	"but.",
	"but_",
	"button",
	"cache",
	"caching",
	"cakephp",
	"calendar",
	"call",
	"camera",
	"campfire",
	"can-",
	"can.",
	"can_",
	"canva",
	"captcha",
	"capture",
	"card",
	"carousel",
	"case",
	"cassandra",
	"cat-",
	"cat.",
	"cat_",
	"category",
	"center",
	"cento",
	"challenge",
	"change",
	"changelog",
	"channel",
	"chart",
	"chat",
	"cheat",
	"check",
	"checker",
	"chef",
	"ches",
	"chinese",
	"chosen",
	"chrome",
	"ckeditor",
	"clas",
	"classe",
	"classic",
	"clean",
	"cli-",
	"cli.",
	"cli_",
	"client",
	"client",
	"clojure",
	"clone",
	"closure",
	"cloud",
	"club",
	"cluster",
	"cms-",
	"cms_",
	"coco",
	"code",
	"coding",
	"coffee",
	"color",
	"combination",
	"combo",
	"command",
	"commander",
	"comment",
	"commit",
	"common",
	"community",
	"compas",
	"compiler",
	"complete",
	"component",
	"composer",
	"computer",
	"computing",
	"con-",
	"con.",
	"con_",
	"concept",
	"conf",
	"config",
	"config",
	"connect",
	"connector",
	"console",
	"contact",
	"container",
	"contao",
	"content",
	"contest",
	"context",
	"control",
	"convert",
	"converter",
	"conway'",
	"cookbook",
	"cookie",
	"cool",
	"copy",
	"cordova",
	"core",
	"couchbase",
	"couchdb",
	"countdown",
	"counter",
	"course",
	"craft",
	"crawler",
	"create",
	"creating",
	"creator",
	"credential",
	"crm-",
	"crm.",
	"crm_",
	"cros",
	"crud",
	"csv-",
	"csv.",
	"csv_",
	"cube",
	"cucumber",
	"cuda",
	"current",
	"currently",
	"custom",
	"daemon",
	"dark",
	"dart",
	"dash",
	"dashboard",
	"data",
	"database",
	"date",
	"day-",
	"day.",
	"day_",
	"dead",
	"debian",
	"debug",
	"debug",
	"debugger",
	"deck",
	"define",
	"del-",
	"del.",
	"del_",
	"delete",
	"demo",
	"deploy",
	"design",
	"designer",
	"desktop",
	"detection",
	"detector",
	"dev-",
	"dev.",
	"dev_",
	"develop",
	"developer",
	"device",
	"devise",
	"diff",
	"digital",
	"directive",
	"directory",
	"discovery",
	"display",
	"django",
	"dns-",
	"dns_",
	"doc-",
	"doc-",
	"doc.",
	"doc.",
	"doc_",
	"doc_",
	"docker",
	"docpad",
	"doctrine",
	"document",
	"doe-",
	"doe.",
	"doe_",
	"dojo",
	"dom-",
	"dom.",
	"dom_",
	"domain",
	"done",
	"don't",
	"dot-",
	"dot.",
	"dot_",
	"dotfile",
	"download",
	"draft",
	"drag",
	"drill",
	"drive",
	"driven",
	"driver",
	"drop",
	"dropbox",
	"drupal",
	"dsl-",
	"dsl.",
	"dsl_",
	"dynamic",
	"easy",
	"_ec2_",
	"ecdsa",
	"eclipse",
	"edit",
	"editing",
	"edition",
	"editor",
	"element",
	"emac",
	"email",
	"embed",
	"embedded",
	"ember",
	"emitter",
	"emulator",
	"encoding",
	"endpoint",
	"engine",
	"english",
	"enhanced",
	"entity",
	"entry",
	"env_",
	"episode",
	"erlang",
	"error",
	"espresso",
	"event",
	"evented",
	"example",
	"example",
	"exchange",
	"exercise",
	"experiment",
	"expire",
	"exploit",
	"explorer",
	"export",
	"exporter",
	"expres",
	"ext-",
	"ext.",
	"ext_",
	"extended",
	"extension",
	"external",
	"extra",
	"extractor",
	"fabric",
	"facebook",
	"factory",
	"fake",
	"fast",
	"feature",
	"feed",
	"fewfwef",
	"ffmpeg",
	"field",
	"file",
	"filter",
	"find",
	"finder",
	"firefox",
	"firmware",
	"first",
	"fish",
	"fix-",
	"fix_",
	"flash",
	"flask",
	"flat",
	"flex",
	"flexible",
	"flickr",
	"flow",
	"fluent",
	"fluentd",
	"fluid",
	"folder",
	"font",
	"force",
	"foreman",
	"fork",
	"form",
	"format",
	"formatter",
	"forum",
	"foundry",
	"framework",
	"free",
	"friend",
	"friendly",
	"front-end",
	"frontend",
	"ftp-",
	"ftp.",
	"ftp_",
	"fuel",
	"full",
	"fun-",
	"fun.",
	"fun_",
	"func",
	"future",
	"gaia",
	"gallery",
	"game",
	"gateway",
	"gem-",
	"gem.",
	"gem_",
	"gen-",
	"gen.",
	"gen_",
	"general",
	"generator",
	"generic",
	"genetic",
	"get-",
	"get.",
	"get_",
	"getenv",
	"getting",
	"ghost",
	"gist",
	"git-",
	"git.",
	"git_",
	"github",
	"gitignore",
	"gitlab",
	"glas",
	"gmail",
	"gnome",
	"gnu-",
	"gnu.",
	"gnu_",
	"goal",
	"golang",
	"gollum",
	"good",
	"google",
	"gpu-",
	"gpu.",
	"gpu_",
	"gradle",
	"grail",
	"graph",
	"graphic",
	"great",
	"grid",
	"groovy",
	"group",
	"grunt",
	"guard",
	"gui-",
	"gui.",
	"gui_",
	"guide",
	"guideline",
	"gulp",
	"gwt-",
	"gwt.",
	"gwt_",
	"hack",
	"hackathon",
	"hacker",
	"hacking",
	"hadoop",
	"haml",
	"handler",
	"hardware",
	"has-",
	"has_",
	"hash",
	"haskell",
	"have",
	"haxe",
	"hello",
	"help",
	"helper",
	"here",
	"hero",
	"heroku",
	"high",
	"hipchat",
	"history",
	"home",
	"homebrew",
	"homepage",
	"hook",
	"host",
	"hosting",
	"hot-",
	"hot.",
	"hot_",
	"house",
	"how-",
	"how.",
	"how_",
	"html",
	"http",
	"hub-",
	"hub.",
	"hub_",
	"hubot",
	"human",
	"icon",
	"ide-",
	"ide.",
	"ide_",
	"idea",
	"identity",
	"idiomatic",
	"image",
	"impact",
	"import",
	"important",
	"importer",
	"impres",
	"index",
	"infinite",
	"info",
	"injection",
	"inline",
	"input",
	"inside",
	"inspector",
	"instagram",
	"install",
	"installer",
	"instant",
	"intellij",
	"interface",
	"internet",
	"interview",
	"into",
	"intro",
	"ionic",
	"iphone",
	"ipython",
	"irc-",
	"irc_",
	"iso-",
	"iso.",
	"iso_",
	"issue",
	"jade",
	"jasmine",
	"java",
	"jbos",
	"jekyll",
	"jenkin",
	"job-",
	"job.",
	"job_",
	"joomla",
	"jpa-",
	"jpa.",
	"jpa_",
	"jquery",
	"json",
	"just",
	"kafka",
	"karma",
	"kata",
	"kernel",
	"keyboard",
	"kindle",
	"kit-",
	"kit.",
	"kit_",
	"kitchen",
	"knife",
	"koan",
	"kohana",
	"lab-",
	"lab-",
	"lab.",
	"lab.",
	"lab_",
	"lab_",
	"lambda",
	"lamp",
	"language",
	"laravel",
	"last",
	"latest",
	"latex",
	"launcher",
	"layer",
	"layout",
	"lazy",
	"ldap",
	"leaflet",
	"league",
	"learn",
	"learning",
	"led-",
	"led.",
	"led_",
	"leetcode",
	"les-",
	"les.",
	"les_",
	"level",
	"leveldb",
	"lib-",
	"lib.",
	"lib_",
	"librarie",
	"library",
	"license",
	"life",
	"liferay",
	"light",
	"lightbox",
	"like",
	"line",
	"link",
	"linked",
	"linkedin",
	"linux",
	"lisp",
	"list",
	"lite",
	"little",
	"load",
	"loader",
	"local",
	"location",
	"lock",
	"log-",
	"log.",
	"log_",
	"logger",
	"logging",
	"logic",
	"login",
	"logstash",
	"longer",
	"look",
	"love",
	"lua-",
	"lua.",
	"lua_",
	"mac-",
	"mac.",
	"mac_",
	"machine",
	"made",
	"magento",
	"magic",
	"mail",
	"make",
	"maker",
	"making",
	"man-",
	"man.",
	"man_",
	"manage",
	"manager",
	"manifest",
	"manual",
	"map-",
	"map-",
	"map.",
	"map.",
	"map_",
	"map_",
	"mapper",
	"mapping",
	"markdown",
	"markup",
	"master",
	"math",
	"matrix",
	"maven",
	"md5",
	"mean",
	"media",
	"mediawiki",
	"meetup",
	"memcached",
	"memory",
	"menu",
	"merchant",
	"message",
	"messaging",
	"meta",
	"metadata",
	"meteor",
	"method",
	"metric",
	"micro",
	"middleman",
	"migration",
	"minecraft",
	"miner",
	"mini",
	"minimal",
	"mirror",
	"mit-",
	"mit.",
	"mit_",
	"mobile",
	"mocha",
	"mock",
	"mod-",
	"mod.",
	"mod_",
	"mode",
	"model",
	"modern",
	"modular",
	"module",
	"modx",
	"money",
	"mongo",
	"mongodb",
	"mongoid",
	"mongoose",
	"monitor",
	"monkey",
	"more",
	"motion",
	"moved",
	"movie",
	"mozilla",
	"mqtt",
	"mule",
	"multi",
	"multiple",
	"music",
	"mustache",
	"mvc-",
	"mvc.",
	"mvc_",
	"mysql",
	"nagio",
	"name",
	"native",
	"need",
	"neo-",
	"neo.",
	"neo_",
	"nest",
	"nested",
	"net-",
	"net.",
	"net_",
	"nette",
	"network",
	"new-",
	"new-",
	"new.",
	"new.",
	"new_",
	"new_",
	"next",
	"nginx",
	"ninja",
	"nlp-",
	"nlp.",
	"nlp_",
	"node",
	"nodej",
	"nosql",
	"not-",
	"not.",
	"not_",
	"note",
	"notebook",
	"notepad",
	"notice",
	"notifier",
	"now-",
	"now.",
	"now_",
	"number",
	"oauth",
	"object",
	"objective",
	"obsolete",
	"ocaml",
	"octopres",
	"official",
	"old-",
	"old.",
	"old_",
	"onboard",
	"online",
	"only",
	"open",
	"opencv",
	"opengl",
	"openshift",
	"openwrt",
	"option",
	"oracle",
	"org-",
	"org.",
	"org_",
	"origin",
	"original",
	"orm-",
	"orm.",
	"orm_",
	"osx-",
	"osx_",
	"our-",
	"our.",
	"our_",
	"out-",
	"out.",
	"out_",
	"output",
	"over",
	"overview",
	"own-",
	"own.",
	"own_",
	"pack",
	"package",
	"packet",
	"page",
	"page",
	"panel",
	"paper",
	"paperclip",
	"para",
	"parallax",
	"parallel",
	"parse",
	"parser",
	"parsing",
	"particle",
	"party",
	"password",
	"patch",
	"path",
	"pattern",
	"payment",
	"paypal",
	"pdf-",
	"pdf.",
	"pdf_",
	"pebble",
	"people",
	"perl",
	"personal",
	"phalcon",
	"phoenix",
	"phone",
	"phonegap",
	"photo",
	"php-",
	"php.",
	"php_",
	"physic",
	"picker",
	"pipeline",
	"platform",
	"play",
	"player",
	"please",
	"plu-",
	"plu.",
	"plu_",
	"plug-in",
	"plugin",
	"plupload",
	"png-",
	"png.",
	"png_",
	"poker",
	"polyfill",
	"polymer",
	"pool",
	"pop-",
	"pop.",
	"pop_",
	"popcorn",
	"popup",
	"port",
	"portable",
	"portal",
	"portfolio",
	"post",
	"power",
	"powered",
	"powerful",
	"prelude",
	"pretty",
	"preview",
	"principle",
	"print",
	"pro-",
	"pro.",
	"pro_",
	"problem",
	"proc",
	"product",
	"profile",
	"profiler",
	"program",
	"progres",
	"project",
	"protocol",
	"prototype",
	"provider",
	"proxy",
	"public",
	"pull",
	"puppet",
	"pure",
	"purpose",
	"push",
	"pusher",
	"pyramid",
	"python",
	"quality",
	"query",
	"queue",
	"quick",
	"rabbitmq",
	"rack",
	"radio",
	"rail",
	"railscast",
	"random",
	"range",
	"raspberry",
	"rdf-",
	"rdf.",
	"rdf_",
	"react",
	"reactive",
	"read",
	"reader",
	"readme",
	"ready",
	"real",
	"reality",
	"real-time",
	"realtime",
	"recipe",
	"recorder",
	"red-",
	"red.",
	"red_",
	"reddit",
	"redi",
	"redmine",
	"reference",
	"refinery",
	"refresh",
	"registry",
	"related",
	"release",
	"remote",
	"rendering",
	"repo",
	"report",
	"request",
	"require",
	"required",
	"requirej",
	"research",
	"resource",
	"response",
	"resque",
	"rest",
	"restful",
	"resume",
	"reveal",
	"reverse",
	"review",
	"riak",
	"rich",
	"right",
	"ring",
	"robot",
	"role",
	"room",
	"router",
	"routing",
	"rpc-",
	"rpc.",
	"rpc_",
	"rpg-",
	"rpg.",
	"rpg_",
	"rspec",
	"ruby-",
	"ruby.",
	"ruby_",
	"rule",
	"run-",
	"run.",
	"run_",
	"runner",
	"running",
	"runtime",
	"rust",
	"rvm-",
	"rvm.",
	"rvm_",
	"salt",
	"sample",
	"sample",
	"sandbox",
	"sas-",
	"sas.",
	"sas_",
	"sbt-",
	"sbt.",
	"sbt_",
	"scala",
	"scalable",
	"scanner",
	"schema",
	"scheme",
	"school",
	"science",
	"scraper",
	"scratch",
	"screen",
	"script",
	"scroll",
	"scs-",
	"scs.",
	"scs_",
	"sdk-",
	"sdk.",
	"sdk_",
	"sdl-",
	"sdl.",
	"sdl_",
	"search",
	"secure",
	"security",
	"see-",
	"see.",
	"see_",
	"seed",
	"select",
	"selector",
	"selenium",
	"semantic",
	"sencha",
	"send",
	"sentiment",
	"serie",
	"server",
	"service",
	"session",
	"set-",
	"set.",
	"set_",
	"setting",
	"setting",
	"setup",
	"sha1",
	"sha2",
	"sha256",
	"share",
	"shared",
	"sharing",
	"sheet",
	"shell",
	"shield",
	"shipping",
	"shop",
	"shopify",
	"shortener",
	"should",
	"show",
	"showcase",
	"side",
	"silex",
	"simple",
	"simulator",
	"single",
	"site",
	"skeleton",
	"sketch",
	"skin",
	"slack",
	"slide",
	"slider",
	"slim",
	"small",
	"smart",
	"smtp",
	"snake",
	"snippet",
	"soap",
	"social",
	"socket",
	"software",
	"solarized",
	"solr",
	"solution",
	"solver",
	"some",
	"soon",
	"source",
	"space",
	"spark",
	"spatial",
	"spec",
	"sphinx",
	"spine",
	"spotify",
	"spree",
	"spring",
	"sprite",
	"sql-",
	"sql.",
	"sql_",
	"sqlite",
	"ssh-",
	"ssh.",
	"ssh_",
	"stack",
	"staging",
	"standard",
	"stanford",
	"start",
	"started",
	"starter",
	"startup",
	"stat",
	"statamic",
	"state",
	"static",
	"statistic",
	"statsd",
	"statu",
	"steam",
	"step",
	"still",
	"stm-",
	"stm.",
	"stm_",
	"storage",
	"store",
	"storm",
	"story",
	"strategy",
	"stream",
	"streaming",
	"string",
	"stripe",
	"structure",
	"studio",
	"study",
	"stuff",
	"style",
	"sublime",
	"sugar",
	"suite",
	"summary",
	"super",
	"support",
	"supported",
	"svg-",
	"svg.",
	"svg_",
	"svn-",
	"svn.",
	"svn_",
	"swagger",
	"swift",
	"switch",
	"switcher",
	"symfony",
	"symphony",
	"sync",
	"synopsi",
	"syntax",
	"system",
	"system",
	"tab-",
	"tab-",
	"tab.",
	"tab.",
	"tab_",
	"tab_",
	"table",
	"tag-",
	"tag-",
	"tag.",
	"tag.",
	"tag_",
	"tag_",
	"talk",
	"target",
	"task",
	"tcp-",
	"tcp.",
	"tcp_",
	"tdd-",
	"tdd.",
	"tdd_",
	"team",
	"tech",
	"template",
	"term",
	"terminal",
	"testing",
	"tetri",
	"text",
	"textmate",
	"theme",
	"theory",
	"three",
	"thrift",
	"time",
	"timeline",
	"timer",
	"tiny",
	"tinymce",
	"tip-",
	"tip.",
	"tip_",
	"title",
	"todo",
	"todomvc",
	"token",
	"tool",
	"toolbox",
	"toolkit",
	"top-",
	"top.",
	"top_",
	"tornado",
	"touch",
	"tower",
	"tracker",
	"tracking",
	"traffic",
	"training",
	"transfer",
	"translate",
	"transport",
	"tree",
	"trello",
	"try-",
	"try.",
	"try_",
	"tumblr",
	"tut-",
	"tut.",
	"tut_",
	"tutorial",
	"tweet",
	"twig",
	"twitter",
	"type",
	"typo",
	"ubuntu",
	"uiview",
	"ultimate",
	"under",
	"unit",
	"unity",
	"universal",
	"unix",
	"update",
	"updated",
	"upgrade",
	"upload",
	"uploader",
	"uri-",
	"uri.",
	"uri_",
	"url-",
	"url.",
	"url_",
	"usage",
	"usb-",
	"usb.",
	"usb_",
	"use-",
	"use.",
	"use_",
	"used",
	"useful",
	"user",
	"using",
	"util",
	"utilitie",
	"utility",
	"vagrant",
	"validator",
	"value",
	"variou",
	"varnish",
	"version",
	"via-",
	"via.",
	"via_",
	"video",
	"view",
	"viewer",
	"vim-",
	"vim.",
	"vim_",
	"vimrc",
	"virtual",
	"vision",
	"visual",
	"vpn",
	"want",
	"warning",
	"watch",
	"watcher",
	"wave",
	"way-",
	"way.",
	"way_",
	"weather",
	"web-",
	"web_",
	"webapp",
	"webgl",
	"webhook",
	"webkit",
	"webrtc",
	"website",
	"websocket",
	"welcome",
	"welcome",
	"what",
	"what'",
	"when",
	"where",
	"which",
	"why-",
	"why.",
	"why_",
	"widget",
	"wifi",
	"wiki",
	"win-",
	"win.",
	"win_",
	"window",
	"wip-",
	"wip.",
	"wip_",
	"within",
	"without",
	"wizard",
	"wjalrxutnfemi/k7mdeng/bpxrficyexamplekey", // example AWS secret key
	"word",
	"wordpres",
	"work",
	"worker",
	"workflow",
	"working",
	"workshop",
	"world",
	"wrapper",
	"write",
	"writer",
	"writing",
	"written",
	"www-",
	"www.",
	"www_",
	"xamarin",
	"xcode",
	"xml-",
	"xml.",
	"xml_",
	"xmpp",
	"xxxxxx",
	"yahoo",
	"yaml",
	"yandex",
	"yeoman",
	"yet-",
	"yet.",
	"yet_",
	"yii-",
	"yii.",
	"yii_",
	"youtube",
	"yui-",
	"yui.",
	"yui_",
	"zend",
	"zero",
	"zip-",
	"zip.",
	"zip_",
	"zsh-",
	"zsh.",
	"zsh_",
}
