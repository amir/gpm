// Package gpm is unofficial Google Play Music API client library
package gpm

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"time"

	"golang.org/x/oauth2"
)

const (
	get  = "GET"
	post = "POST"

	typeTrack  = "1"
	typeArtist = "2"
	typeAlbum  = "3"
)

var (
	apiEndpoint             = "https://www.googleapis.com/sj/v1"
	googleClientLogin       = "https://www.google.com/accounts/ClientLogin"
	googlePlayMusicEndpoint = "https://play.google.com/music"
)

// Client represents a connection to Google Play Music
type Client struct {
	oauthConfig *oauth2.Config
	token       *oauth2.Token
	httpClient  *http.Client
}

// Artist represents metadata of an artist (kind: sj#artist)
type Artist struct {
	ID     string
	Name   string
	Albums []Album
}

// Album represents metadata of an album (kind: sj#album)
type Album struct {
	ID     string
	Name   string
	Artist string
	Year   uint16
	Tracks []Track
}

// Track represents the metadata of a track (kind: sj#track)
type Track struct {
	ID             string
	Nid            string
	Title          string
	Album          string
	AlbumID        string
	Artist         string
	DurationMillis string
	TrackNumber    int64
	Year           int64
}

// TrackList represents a list of Tracks (kind: sj#tracklist)
type TrackList struct {
	Data struct {
		Items []Track
	}
}

// Settings represents user's Google Play Music settings
type Settings struct {
	Settings struct {
		Labs    []map[string]string
		Devices []map[string]interface{}
	}
}

// (kind: sj#playlistEntryList)
type PlaylistEntryList struct {
	Data struct {
		Items []PlaylistEntry
	}
}

// (kind: sj#playlistEntry)
type PlaylistEntry struct {
	PlaylistID string
	Track      Track
}

// (kind: sj#playlistList)
type PlaylistList struct {
	Data struct {
		Items []Playlist
	}
}

// (kind: sj#playlist)
type Playlist struct {
	ID                    string
	Name                  string
	LastModifiedTimestamp string
}

// New allocates a Google Play Music client with the given OAuth auth code.  Obtain a new Auth Code https://developers.google.com/oauthplayground/, by entering "https://www.googleapis.com/auth/musicmanager" in the "Input your own scopes" input box.  WARN: Do not click "Exchange auth. code for tokens" on Step 2!
func New(clientID, clientSecret string) (client *Client) {
	client = new(Client)
	client.oauthConfig = &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		Scopes: []string{
			"https://www.googleapis.com/auth/musicmanager",
		},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://accounts.google.com/o/oauth2/token",
		},
	}
	jar, _ := cookiejar.New(nil)
	client.httpClient = &http.Client{
		Jar: jar,
	}

	return
}

// Login tries to get authorization token from Google Login service
func (client *Client) AuthURL() string {
	return client.oauthConfig.AuthCodeURL("none")
}

func (client *Client) DoAuth(authCode string) (err error) {
	tok, err := client.oauthConfig.Exchange(oauth2.NoContext, authCode)
	if err != nil {
		return
	}

	client.token = tok
	client.httpClient.Transport = &oauth2.Transport{
		Source: client.oauthConfig.TokenSource(oauth2.NoContext, tok),
	}

	req, err := http.NewRequest("HEAD", googlePlayMusicEndpoint+"/listen", nil)
	if err != nil {
		return
	}
	_, err = client.httpClient.Do(req)

	return
}

// makeWebServiceCall is where required headers are set before calling Google web services
func (client *Client) makeWebServiceCall(method, url string, data url.Values, headers map[string]string) (body []byte, err error) {
	if len(data) > 0 {
		url += "?" + data.Encode()
	}
	redirectedURL := ""
	client.httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		redirectedURL = req.URL.String()
		return nil
	}
	req, err := http.NewRequest(method, url, nil)
	client.token.SetAuthHeader(req)
	for key, value := range headers {
		req.Header.Add(key, value)
	}
	resp, err := client.httpClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if redirectedURL != "" {
		body = []byte(redirectedURL)
	} else {
		body, err = ioutil.ReadAll(resp.Body)
	}

	return
}

// TrackList returns list of tracks uploaded by user to Google Play Music
func (client *Client) TrackList() (tracks TrackList, err error) {
	body, err := client.makeWebServiceCall(post, apiEndpoint+"/trackfeed", nil, nil)

	json.Unmarshal(body, &tracks)

	return
}

// SearchAllAccess searches Google Play Music All Access
func (client *Client) SearchAllAccess(query string, maxResults int) (body []byte, err error) {
	data := url.Values{
		"q":           {query},
		"max-results": {strconv.Itoa(maxResults)},
	}
	body, err = client.makeWebServiceCall(get, apiEndpoint+"/query", data, nil)

	return
}

// SearchAllAccessTracks searches Google Play Music All Access for tracks matching query
func (client *Client) SearchAllAccessTracks(query string, maxResults int) (tracks []Track, err error) {
	searchResponse, err := client.SearchAllAccess(query, maxResults)
	if err != nil {
		return
	}

	var data struct {
		Entries []struct {
			Type  string
			Track Track
		}
	}
	err = json.Unmarshal(searchResponse, &data)
	if err != nil {
		return
	}

	for _, e := range data.Entries {
		if e.Type != typeTrack {
			continue
		}
		tracks = append(tracks, e.Track)
	}

	return
}

// SearchAllAccessAlbums searches Google Play Music All Access for albums matchin query
func (client *Client) SearchAllAccessAlbums(query string, maxResults int) (albums []Album, err error) {
	print(query)
	searchResponse, err := client.SearchAllAccess(query, maxResults)
	if err != nil {
		return
	}

	var tmp map[string]interface{}
	err = json.Unmarshal(searchResponse, &tmp)
	if err != nil {
		return
	}
	if tmp["entries"] != nil {
		for _, e := range tmp["entries"].([]interface{}) {
			entry := e.(map[string]interface{})
			if entry["type"] == typeAlbum {
				album := entry["album"].(map[string]interface{})
				albums = append(albums, Album{
					ID:     album["albumId"].(string),
					Name:   album["name"].(string),
					Artist: album["artist"].(string),
					Year:   uint16(album["year"].(float64)),
				})
			}
		}
	}

	return
}

// Settings loads user's Google Play Music service settings
func (client *Client) Settings() (settings Settings, err error) {
	u, _ := url.Parse(googlePlayMusicEndpoint)
	cookies := client.httpClient.Jar.Cookies(u)
	data := url.Values{}
	for _, c := range cookies {
		if c.Name == "xt" {
			data.Set("xt", c.Value)
		}
	}
	resp, err := client.makeWebServiceCall(post,
		googlePlayMusicEndpoint+"/services/loadsettings", data, nil)
	if err != nil {
		return
	}

	json.Unmarshal(resp, &settings)

	return
}

func (client *Client) Playlists() ([]Playlist, error) {
	resp, err := client.makeWebServiceCall(post, apiEndpoint+"/playlistfeed", nil, nil)
	if err != nil {
		return nil, err
	}
	var playlistsList PlaylistList

	json.Unmarshal(resp, &playlistsList)

	return playlistsList.Data.Items, nil
}

func (client *Client) PlaylistEntries() (playlistEntries []PlaylistEntry, err error) {
	resp, err := client.makeWebServiceCall(post, apiEndpoint+"/plentryfeed", nil, nil)
	var playlistEntriesList PlaylistEntryList

	json.Unmarshal(resp, &playlistEntriesList)

	return playlistEntriesList.Data.Items, nil
}

// ArtistInfo returns metadata associated with artist ID
func (client *Client) ArtistInfo(artistID string, includeAlbums bool) (artist Artist, err error) {
	data := url.Values{
		"nid": {artistID},
		"alt": {"json"},
	}
	if includeAlbums {
		data.Set("include-albums", "True")
	}

	resp, err := client.makeWebServiceCall(get,
		apiEndpoint+"/fetchartist", data, nil)

	json.Unmarshal(resp, &artist)

	return
}

// AlbumInfo returns metadata associated with album ID
func (client *Client) AlbumInfo(albumID string, includeTracks bool) (album Album, err error) {
	data := url.Values{
		"nid": {albumID},
		"alt": {"json"},
	}
	if includeTracks {
		data.Set("include-tracks", "True")
	}

	resp, err := client.makeWebServiceCall(get,
		apiEndpoint+"/fetchalbum", data, nil)

	json.Unmarshal(resp, &album)

	return
}

// TrackInfo returns metadata associated with track ID
func (client *Client) TrackInfo(trackID string) (track Track, err error) {
	data := url.Values{
		"nid": {trackID},
		"alt": {"json"},
	}
	headers := make(map[string]string)
	headers["Content-Type"] = "application/json"
	resp, err := client.makeWebServiceCall(get,
		apiEndpoint+"/fetchtrack", data, headers)

	json.Unmarshal(resp, &track)

	return
}

// MP3StreamURL returns a streamable URL of the track ID
func (client *Client) MP3StreamURL(trackID, deviceID string) (mp3Url string, err error) {
	key := []byte("34ee7983-5ee6-4147-aa86-443ea062abf774493d6a-2a15-43fe-aace-e78566927585\n")
	mac := hmac.New(sha1.New, key)
	mac.Write([]byte(trackID))
	now := time.Now()
	salt := strconv.FormatInt(now.Unix()*1000, 10)
	mac.Write([]byte(salt))
	sig := base64.URLEncoding.EncodeToString(mac.Sum(nil))
	sig = sig[0 : len(sig)-1]
	headers := make(map[string]string)
	headers["X-Device-ID"] = deviceID

	data := url.Values{
		"opt": {"hi"},
		"net": {"wifi"},
		"pt":  {"e"},
		"sig": {sig},
		"slt": {salt},
	}

	if trackID[0:1] == "T" {
		data.Set("mjck", trackID)
	} else {
		data.Set("songid", trackID)
	}

	resp, err := client.makeWebServiceCall(get,
		"https://android.clients.google.com/music/mplay", data, headers)
	if err != nil {
		return
	}
	mp3Url = string(resp)

	return
}
