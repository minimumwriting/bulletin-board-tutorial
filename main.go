package main

import (
	"crypto/sha256"
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

//세션저장소
//암호화 키는 32길이의 임의의 바이트 문자열
var store = sessions.NewCookieStore([]byte(securecookie.GenerateRandomKey(32)))

//게시글
type txt struct {
	//게시글의 고유 식별번호
	ID int
	//게시글의 제목
	Title string
	//게시글의 본문
	Body string
	//게시글의 게시 시간
	Time int64
	//게시글 작성자
	Writer string
}

//"/"를 처리하는 핸들러
type rootHandler struct {
	DB *sql.DB //"/"에서 사용될 DB
}

func (h rootHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s, err := store.Get(r, "auth") //세션에서 사용자의 정보를 불러옴
	if err != nil {
		log.Println(err)
		return
	}

	name := ""                         //사용자의 이름
	isLogin := false                   //사용자가 로그인을 했는지 여부
	if _, ok := s.Values["name"]; ok { //만약 사용자의 정보가 있다면
		isLogin = true
		name = s.Values["name"].(string)
	}

	tmpl, err := template.ParseFiles("root.gotmpl") //root.gotmpl go 템플릿 파일을 파싱
	if err != nil {
		log.Println(err)
		return
	}

	contents := make([]txt, 0) //게시글들을 담을 배열

	rows, err := h.DB.Query("select * from txt") //DB에서 모든 게시글을 불러옴
	defer rows.Close()

	for rows.Next() {
		var id int        //게시글 고유 식별번호
		var title string  //게시글 제목
		var body string   //게시글 본문
		var time int64    //게시글 작성 시간
		var writer string //게시글 작성자

		rows.Scan(&id, &title, &time, &body, &writer)

		contents = append(contents, txt{id, title, body, time, writer})
	}

	err = tmpl.Execute(w, struct { //템플릿 파일로 html문서 생성
		TimeToString func(int64) string //UNIX 시간을 문자열로 변환하는 함수
		IsLogin      bool               //로그인 했는가
		User         string             //사용자 이름
		Contents     []txt              //모든 게시글들
	}{
		TimeToString: func(x int64) string {
			return time.Unix(x, 0).String()
		},
		IsLogin:  isLogin,
		User:     name,
		Contents: contents,
	})
	if err != nil {
		log.Println(err)
	}
}

//회원가입을 처리하는 handler
// /newuser
type newUserHandler struct {
	DB *sql.DB //회원가입에 사용될 DB
}

func (h newUserHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer fmt.Fprintf(w, `<script>location.href="/"</script>`) //함수가 끝나면 "/"로 이동
	session, err := store.Get(r, "auth")                       //세션에서 사용자의 정보를 불러옴
	if err != nil {
		log.Println(err)
		return
	}

	err = r.ParseForm() //http request으로 전달된 form값을 파싱
	if err != nil {
		log.Println(err)
		return
	}

	name := r.FormValue("name")                                                   //이름
	password := fmt.Sprintf("%x", sha256.Sum256([]byte(r.FormValue("password")))) //비밀번호

	var count int

	err = h.DB.QueryRow("select count(*) from user where name=?", name).Scan(&count) //DB에서 이름이 같은 회원의 수를 셈
	if err != nil {
		log.Println(err)
		return
	}

	if count != 0 { //만약 이름이 같은 회원이 존재한다면
		fmt.Fprint(w, `<script> alert("sign up failed"); </script>`) //회원가입 실패를 알림
		return
	}

	//DB에 새 사용자를 저장
	_, err = h.DB.Exec("insert into user (name,password) values(?,?)", name, password)
	if err != nil {
		log.Println(err)
		return
	}

	session.Values["name"] = name //세션에 새 사용자 정보를 저장
	if err := session.Save(r, w); err != nil {
		log.Println(err)
		return
	}
}

//로그인을 처리하는 핸들러
//"/login"
type loginHandler struct {
	DB *sql.DB //로그인에서 사용될 DB
}

func (h loginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer fmt.Fprintf(w, `<script>location.href="/"</script>`) //함수가 끝나면 "/"로 이동

	session, err := store.Get(r, "auth") //사용자의 정보를 세션에서 불러옴
	if err != nil {
		log.Println(err)
		return
	}

	err = r.ParseForm() // http request에서 form을 파싱
	if err != nil {
		log.Println(err)
		return
	}

	name := r.FormValue("name")         //이름
	password := r.FormValue("password") //비밀번호

	var count int

	//이름과 비밀번호가 일치하는 유저의 수를 DB에서 찾음
	err = h.DB.QueryRow("select count(*) from user where name=? and password=?", name, fmt.Sprintf("%x", sha256.Sum256([]byte(password)))).Scan(&count)
	if err != nil {
		log.Println(err)
		return
	}

	if count != 1 { //존재하지 않는다면
		fmt.Fprint(w, `<script> alert("login failed"); </script>`)
		return
	}

	session.Values["name"] = name //사용자의 이름을 세션에 저장
	if err := session.Save(r, w); err != nil {
		log.Println(err)
		return
	}
}

//로그아웃을 처리하는 핸들러
//"/logout"
type logoutHandler struct {
	DB *sql.DB
}

func (h logoutHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer fmt.Fprintf(w, `<script>location.href="/"</script>`) //함수가 끝나면 "/"로 이동
	session, err := store.Get(r, "auth")                       //세션에서 사용자의 정보 불러옴
	if err != nil {
		log.Println(err)
		return
	}

	delete(session.Values, "name") //세션에서 사용자의 이름 삭제
	if err := session.Save(r, w); err != nil {
		log.Println(err)
		return
	}
}

//게시글 작성을 처리하는 핸들러
type writeHandler struct {
	DB *sql.DB
}

func (h writeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer fmt.Fprintf(w, `<script>location.href="/"</script>`) //함수가 끝나면 "/"로 이동
	session, err := store.Get(r, "auth")                       //세션에서 사용자의 정보 불러오기
	if err != nil {
		log.Println(err)
		return
	}

	if _, ok := session.Values["name"]; ok == false { //세션에 사용자의 이름이 없다면
		return
	}

	err = r.ParseForm() //http request에서 form 값을 파싱
	if err != nil {
		log.Println(err)
		return
	}

	title := r.FormValue("title") //새 게시글의 제목
	body := r.FormValue("body")   //새 게시글의 본문

	_, err = h.DB.Exec("insert into txt (title,body,time,writer) values(?,?,?,?)", title, body, time.Now().Unix(), session.Values["name"])
	if err != nil {
		log.Println(err)
		return
	}
}

//게시글 조회를 처리하는 핸들러
//"/show/{id : 숫자}"
type showHandler struct {
	DB *sql.DB
}

func (h showHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)                 //URL을 파싱
	id, err := strconv.Atoi(vars["id"]) //URL에서 게시글 식별번호를 불러옴
	if err != nil {
		log.Println(err)
		return
	}

	var title string  //제목
	var body string   //본문
	var writer string //작성자
	var T int64       //작성 시간

	tmpl, err := template.ParseFiles("show.gotmpl") //"show.gotmpl" 템플릿 파일을 파싱함
	if err != nil {
		log.Println(err)
		return
	}

	row := h.DB.QueryRow("select title,time,body,writer from txt where id=?", id) //식별번호로 DB에서 게시글을 찾음
	if err := row.Scan(&title, &T, &body, &writer); err != nil {
		log.Println(err)
		return
	}

	err = tmpl.Execute(w, struct { //템플릿 파일로 html문서 생성
		Func   func(int64) string //UNIX 시간을 문자열로 변환 함수
		Title  string             //게시글 제목
		Body   string             //게시글 본문
		Time   int64              //게시글 작성 시간
		Writer string             //게시글 작성자
	}{
		Func: func(x int64) string {
			return time.Unix(x, 0).String()
		},
		Title:  title,
		Body:   body,
		Time:   T,
		Writer: writer,
	})
	if err != nil {
		log.Println(err)
	}

}

func init() {
	//세션ID 쿠키 설정
	store.Options.MaxAge = 15 * 60
	store.Options.HttpOnly = true
}

func main() {
	//연결하려는 mysql의 정보
	//username:password@protocol(address)/dbname?param=value
	conn := os.Args[1]
	db, err := sql.Open("mysql", conn) //mysql에 연결
	if err != nil {
		log.Panic(err)
	}

	r := mux.NewRouter()

	r.Handle("/", rootHandler{
		db,
	})

	r.Handle("/newuser", newUserHandler{
		db,
	}).Methods("POST")

	r.Handle("/login", loginHandler{
		db,
	})

	r.Handle("/logout", logoutHandler{
		db,
	})

	r.HandleFunc("/newuserform", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "newuserform.html")
	})

	r.Handle("/write", writeHandler{
		db,
	})

	r.HandleFunc("/writeform", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, "writeform.html")
	})

	r.Handle("/show/{id:[0-9]+}", showHandler{
		db,
	})

	log.Println("server start")
	http.ListenAndServe(":8080", r)
}
