# lchttp:
lchttp is a lightweight C http request library used to generate request strings to be sent to a webserver. Goals are to be minimal and easy to understand as such we don't make any attempt to send traffic to the socket for you. We simply take in the headers, path, method and data you give us to generate a HTTP request string that can be sent to a server to complete a HTTP request.

Sending and reading the servers response is your job and we make no attempt to handle that.

## how it works:
As an example of how our library works we will show you a demonstartion here in psudeo code there is also the examples folder which shows an example usage to connect to google and get the `/` page.

```c
    int main() {
        int socketfd;
        lchttp_ret_t ret;
        lchttp_request_t *request = lchttp_new_request();
		if(request == NULL) {/*handle error*/}
        
        /*
         *request configuration functions are named with set or add
         *Set are functions that are required for the request to build,
         *Set functions also do not allocate so if you allocate 4 bytes for 
         *The string "GET" you would need to free that
         *
         *Add functions on the other hand are headers and data things that may
         *not be needed in every HTTP request and are thus optional. They Allocate 
         *data internally which is freed at the same time the request is freed
         */
        
        /*needed*/
        lchttp_request_set_method(request, "GET");
        lchttp_request_set_path(request, "/");
        lchttp_request_set_http_version(request, "HTTP/1.0");

        /*optional*/
        ret = lchttp_request_add_header(request, "Host", "localhost");
        if(ret == LCHTTP_MEMORY_ALLOC) {/*Memory allocation error*/}
    
        /*once you are satisfied you can call lchttp_request_build
         * this will alocate memory and construct a HTTP string 
         * which can be reterived by calling lchttp_request_get_str
         * NOTE: YOU DO NOT HAVE TO FREE THIS STRING 
         * it like request headers is freed upon freeing the request 
         */
        ret = lchttp_request_build(request);
        if(ret == LCHTTP_MEMORY_ALLOC) {/*Memory allocation error*/}

        const char *str = lchttp_request_get_str(request);
        if(str == NULL) {/*Do some error*/}

        /*now send your data to the socket*/
        send(socketfd, str, strlen(str), 0);
        
        /*free request and all data associated*/
        lchttp_request_free(request);
    }

```
Included in here are if statements for functions that can error but without any follow up code on how to handle that error as that falls out of scope. Of this example

## What it works on:
We should work fine on any platform as we are using C stdlibrary and nothing else and where we give you the raw request string it should be able to intergrated in to C on 
any platform wheter that be Linux, MAC OSX, BSD, or Windows.

However I do not own all these systems so if there are bugs relating to a certain system please let me know

## How to use it:
To include this in to your project either just include it in your projects local source tree. Or to install it system wide install it in your systems shared library folder and includes search folder.

## Bug reporting:
If you find a bug please report it. Ideally the more info you can provide the better but if you can provide steps to reproduce that will help a lot.

## Other Issues:
if you have other issues or suggestions they are welcome in github issues page or pull requests are welcome. But where we aim to keep the library relatively simple they may not always be accpeted. But of course your more than welcome to fork this code and continue it however you feel best. :3
# lchttp
