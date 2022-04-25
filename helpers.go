package ibmcloudsecrets

import (
	"io/ioutil"
	"net/http"
)

func httpRequest(client *http.Client, r *http.Request) ([]byte, int, error) {
	resp, err := client.Do(r)
	if err != nil {
		return nil, 0, err
	}
	defer closeResponse(resp)

	var body []byte
	if resp.Body != nil {
		body, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, resp.StatusCode, err
		}
	}

	return body, resp.StatusCode, nil
}

func closeResponse(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}
