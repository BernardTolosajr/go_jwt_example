package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/mitchellh/mapstructure"
	"github.com/urfave/negroni"
)

var mySigningKey = []byte("secret")

type Product struct {
	Id          int
	Name        string
	Slug        string
	Description string
}

type User struct {
	Name string `json:"name"`
}

type Exception struct {
	Message string `json:"message"`
}

var products = []Product{
	Product{Id: 1, Name: "Hover Shooters", Slug: "hover-shooters", Description: "Shoot your way to the top on 14 different hoverboards"},
	Product{Id: 2, Name: "Ocean Explorer", Slug: "ocean-explorer", Description: "Explore the depths of the sea in this one of a kind underwater experience"},
	Product{Id: 3, Name: "Dinosaur Park", Slug: "dinosaur-park", Description: "Go back 65 million years in the past and ride a T-Rex"},
	Product{Id: 4, Name: "Cars VR", Slug: "cars-vr", Description: "Get behind the wheel of the fastest cars in the world."},
	Product{Id: 5, Name: "Robin Hood", Slug: "robin-hood", Description: "Pick up the bow and arrow and master the art of archery"},
	Product{Id: 6, Name: "Real World VR", Slug: "real-world-vr", Description: "Explore the seven wonders of the world in VR"},
}

var ProductsHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	decoded := context.Get(r, "user")

	var user User

	mapstructure.Decode(decoded.(jwt.MapClaims), &user)

	fmt.Print(user.Name)

	payload, _ := json.Marshal(products)

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(payload))
})

/* Handlers */
var GetTokenHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	/* Create the token */
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)

	/* Set token claims */
	claims["name"] = "bernard"
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	/* Sign the token with our secret */
	tokenString, _ := token.SignedString(mySigningKey)

	/* Finally, write the token to the browser window */
	w.Write([]byte(tokenString))
})

func AuthMiddleware(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	authorizationHeader := r.Header.Get("authorization")
	bearerToken := strings.Split(authorizationHeader, " ")
	if len(bearerToken) == 2 {
		token, error := jwt.Parse(bearerToken[1], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("There was an error")
			}
			return []byte("secret"), nil
		})

		if error != nil {
			w.WriteHeader(http.StatusUnauthorized)
			json.NewEncoder(w).Encode(Exception{Message: error.Error()})
			return
		}

		if token.Valid {
			context.Set(r, "user", token.Claims)
			next(w, r)
		} else {
			json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
		}

		next(w, r)
	} else {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(Exception{Message: "Invalid authorization token"})
	}
}

func main() {
	r := mux.NewRouter()

	r.Handle("/login", GetTokenHandler).Methods("GET")
	r.Handle("/products", negroni.New(
		negroni.HandlerFunc(AuthMiddleware),
		negroni.Wrap(ProductsHandler),
	)).Methods("GET")

	http.ListenAndServe(":3000", r)
}
