#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#define CURL_STATICLIB 
#include <curl/curl.h>
#include <json-c/json.h>
#include <signal.h>
#include <syslog.h>
#include <getopt.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdbool.h>
/* This program is the Unix installation of the client */



/* holder for curl fetch */
struct curl_fetch_st {
    char *payload;
    size_t size;
};
/* declare variables */
static char *conf_file_name = "home/malware/vm_shared/testReport.json";
static char *conf_file_profiles = "home/malware/vm_shared/testProfiles.json";
static char *pid_file_name = "pid_log.txt";
static char *log_file_name = "error_log.txt";
static char *app_name = "AVIRclientdaemon";
static int pid_fd = -1;
static int running = 0;
static int delay = 500;
static int counter = 0;
static FILE *log_stream;
static char *url_IncidentReport ="https://10.0.2.2:7106/api/IncidentReport";
static char *url_ThreatReport ="https://10.0.2.2:7106/api/ThreatProfile";
json_object *json_root = NULL;
json_object *jobj = NULL;


/**
 * This function will demonize the process
 */
static void daemonize()
{
	pid_t pid = 0;
	int fd;

	/* Fork off the parent process */
	pid = fork();

	/* An error occurred */
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	/* Success: Let the parent terminate */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* On success: The child process becomes session leader */
	if (setsid() < 0) {
		exit(EXIT_FAILURE);
	}

	/* Ignore signal sent from child to parent process */
	signal(SIGCHLD, SIG_IGN);

	/* Fork off for the second time*/
	pid = fork();

	/* An error occurred */
	if (pid < 0) {
		exit(EXIT_FAILURE);
	}

	/* Success: Let the parent terminate */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* Set new file permissions */
	umask(0);

	/* Change the working directory to the root directory */
	/* or another appropriated directory */
	chdir("/");

	/* Close all open file descriptors */
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        close (x);
    }

	// /* Reopen stdin (fd = 0), stdout (fd = 1), stderr (fd = 2) */
	// stdin = fopen("/dev/null", "r");
	// stdout = fopen("/dev/null", "w+");
	// stderr = fopen("/dev/null", "w+");

	// /* Try to write PID of daemon to lockfile */
	// if (pid_file_name != NULL)
	// {
	// 	char str[256];
	// 	pid_fd = open(pid_file_name, O_RDWR|O_CREAT, 0640);
	// 	if (pid_fd < 0) {
	// 		/* Can't open lockfile */
	// 		exit(EXIT_FAILURE);
	// 	}
	// 	if (lockf(pid_fd, F_TLOCK, 0) < 0) {
	// 		/* Can't lock file */
	// 		exit(EXIT_FAILURE);
	// 	}
	// 	/* Get current PID */
	// 	sprintf(str, "%d\n", getpid());
	// 	/* Write PID to lockfile */
	// 	write(pid_fd, str, strlen(str));
	// }
}
/**
 * This function clears report file
 */
void clearFile()
{
  fclose(fopen(conf_file_name, "w"));
}
/**
 * This function appends profiles to a flat file
 */
static bool addProfile(){
      // create file if it doesn't exist
    FILE* fp;

    fp = fopen(conf_file_profiles, "r");
    if (!fp)
    {
       fp = fopen(conf_file_profiles, "w");
       if (!fp)
           return 0;
       fputs("[]", fp);
       fclose(fp);
    }

     // add the document to the file
    fp = fopen(conf_file_profiles, "rb+"); 
    if(fp)
    {
        // check if first is [
       fseek(fp, 0, SEEK_SET);
       if (getc(fp) != '[')
       {
           fclose(fp);
          return FALSE;
       }
       // is array empty?
       bool is_empty = FALSE;
       if (getc(fp) == ']')
           is_empty = TRUE;

      // check if last is ]
       fseek(fp, -1, SEEK_END);
       if (getc(fp) != ']')
       {
           fclose(fp);
           return FALSE;
       }

      // replace ] by ,
        fseek(fp, -1, SEEK_END);
        if (!is_empty)
            fputc(',', fp);

       // append the document
       fputs(json_object_to_json_string(jobj), fp);

       // close the array
       fputc(']', fp);
       fclose(fp);

       return TRUE;
    }
    return FALSE;
}

/* callback for curl fetch */
size_t curl_callback (void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;                             /* calculate buffer size */
    struct curl_fetch_st *p = (struct curl_fetch_st *) userp;   /* cast pointer to fetch struct */

    /* expand buffer */
    p->payload = (char *) realloc(p->payload, p->size + realsize + 1);

    /* check buffer */
    if (p->payload == NULL) {
      /* this isn't good */
      fprintf(stderr, "ERROR: Failed to expand buffer in curl_callback");
      /* free buffer */
      free(p->payload);
      /* return */
      return -1;
    }

    /* copy contents to buffer */
    memcpy(&(p->payload[p->size]), contents, realsize);

    /* set new buffer size */
    p->size += realsize;

    /* ensure null termination */
    p->payload[p->size] = 0;

    /* return size */
    return realsize;
}

/* fetch and return url body via curl */
CURLcode curl_fetch_url(CURL *ch, const char *url, struct curl_fetch_st *fetch) {
    CURLcode rcode;                   /* curl result code */

    /* init payload */
    fetch->payload = (char *) calloc(1, sizeof(fetch->payload));

    /* check payload */
    if (fetch->payload == NULL) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to allocate payload in curl_fetch_url");
        /* return error */
        return CURLE_FAILED_INIT;
    }

    /* init size */
    fetch->size = 0;

    /* set url to fetch */
    curl_easy_setopt(ch, CURLOPT_URL, url);

    /* set calback function */
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, curl_callback);

    /* pass fetch struct pointer */
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, (void *) fetch);

    /* set default user agent */
    curl_easy_setopt(ch, CURLOPT_USERAGENT, "libcurl-agent/1.0");

    /* set timeout */
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, 5);

    /* enable location redirects */
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1);

    /* set maximum allowed redirects */
    curl_easy_setopt(ch, CURLOPT_MAXREDIRS, 1);

    /* fetch the url */
    rcode = curl_easy_perform(ch);

    /* return */
    return rcode;
}
/* This functions sends incident reports */
int postRequest(char *url, char *endpoint){
    CURL *ch;                                               /* curl handle */
    CURLcode rcode;                                         /* curl result code */

    json_object *json;                                      /* json post body */
    enum json_tokener_error jerr = json_tokener_success;    /* json parse error */

    struct curl_fetch_st curl_fetch;                        /* curl fetch struct */
    struct curl_fetch_st *cf = &curl_fetch;                 /* pointer to fetch struct */
    struct curl_slist *headers = NULL;                      /* http headers to send with request */
    jobj = NULL;

    /* url to test site */
    /* char *url = "https://localhost:7106/api/IncidentReport"; */

    /* init curl handle */
    if ((ch = curl_easy_init()) == NULL) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to create curl handle in fetch_session");
        /* return error */
        return 1;
    }

    /* set content type */
    headers = curl_slist_append(headers, "Accept: application/json");
    headers = curl_slist_append(headers, "Content-Type: application/json");

    /* set curl options */
    curl_easy_setopt(ch, CURLOPT_CUSTOMREQUEST, "POST");
    curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(ch, CURLOPT_POSTFIELDS, json_object_to_json_string(json_root));
    //TEST enviroment only
    curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, FALSE);
    curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, FALSE);    


    /* fetch page and capture return code */
    rcode = curl_fetch_url(ch, url, cf);

    /* cleanup curl handle */
    curl_easy_cleanup(ch);

    /* free headers */
    curl_slist_free_all(headers);

    /* free json object */
    json_object_put(json_root);

    /* check return code */
    if (rcode != CURLE_OK || cf->size < 1) {
        /* log error */
        fprintf(stderr, "ERROR: Failed to fetch url (%s) - curl said: %s \n",
            url, curl_easy_strerror(rcode));
            syslog(LOG_INFO,  "ERROR: Failed to fetch url (%s) - curl said: %s \n",
            url, curl_easy_strerror(rcode));
        /* return error */
        return 2;
    }

    /* check payload */
    if (cf->payload != NULL) {
        /* print result */
        printf("CURL Returned: \n%s\n", cf->payload);
        /* parse return */
        json = json_tokener_parse_verbose(cf->payload, &jerr);
        /* free payload */

        free(cf->payload);
    } else {
        /* error */
        fprintf(stderr, "ERROR: Failed to populate payload");
        /* free payload */
        free(cf->payload);
        /* return */
        return 3;
    }

    /* check error */
    if (jerr != json_tokener_success) {
        /* error */
        fprintf(stderr, "ERROR: Failed to parse json string\n");
        /* free json object */
        json_object_put(json);
        /* return */
        return 4;
    }

    //set return object
     jobj = json;

    /* debugging */
    /* printf("Parsed JSON: %s\n", json_object_to_json_string(json_root)); */

    /* exit */
    return 0;
}
/* This functions creates json objects */
 int parseJson(){

   json_root = json_object_from_file(conf_file_name);
   if (!json_root)
      return 1;
   //printf("The json file:\n\n%s\n", json_object_to_json_string(root));
   //json_object_put(root);
  
  return 0;
}
/**
 * This function requests threat profiles
 */
int getThreatProfile(){

    json_object *jrequest = json_object_new_object();    
    //create threat request
    json_object_object_add(jrequest, "incidentreportid", jobj);
    json_root = jrequest;

    if(postRequest(url_ThreatReport, "t") == 0){
     //save scores
     addProfile();
    }

    return 0;

}
/**
 * This function reports incidents
 */
int reportIncident(const char* filename){

  parseJson();

  if(json_root != NULL)
  {
    
     //fprintf(log_stream, "Debug: send report.\n");

     if(postRequest(url_IncidentReport,"r") == 0){
       
      //Delete request once it was sent
      //clearFile();
      //Get threat profile
      if (json_object_object_get_ex(jobj, "id", &jobj)) {   
       
          getThreatProfile();
          
          }
     }
  }

 return 0;
}
/**
 * This function handles signals
 */
void handle_signal(int signo)
{
	if (signo == SIGINT) {
		fprintf(log_stream, "Debug: stopping daemon ...\n");
		/* Unlock and close lockfile */
		if (pid_fd != -1) {
			lockf(pid_fd, F_ULOCK, 0);
			close(pid_fd);
		}
		/* Try to delete lockfile */
		if (pid_file_name != NULL) {
			unlink(pid_file_name);
		}
		
		/* Reset signal handling to default behavior */
		signal(SIGINT, SIG_DFL);
	} else if (signo == SIGHUP) {
		fprintf(log_stream, "Debug: reloading daemon config file ...\n");
		//read_conf_file(1);
	} else if (signo == SIGUSR1) {
		//fprintf(log_stream, "Debug: received SIGUSR1 signal\n");
        syslog(LOG_INFO, "Debug: received SIGUSR1 signal\n");
        reportIncident("r");
	}
}
/* Main function */
int main()
{  
    int value, ret;
    daemonize();
    /* Open system log and write message to it */
	openlog(app_name, LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, "Started %s", app_name);

	/* Daemon will handle three signals */
	signal(SIGINT, handle_signal); //stop
	signal(SIGHUP, handle_signal); //reconfigure
    signal(SIGUSR1, handle_signal); //send report

    /* This global variable can be changed in function handling signal */
	running = 1;
    /* Never ending loop of server */
	while (running == 1) {
		/* Debug print */
		// ret = fprintf(log_stream, "Debug: %d\n", counter++);

		
		sleep(delay);
        break;

	}

	/* Write system log and close it. */
	syslog(LOG_INFO, "Stopped %s", app_name);
	closelog();

	/* Free allocated memory */
	if (conf_file_name != NULL) free(conf_file_name);
	if (log_file_name != NULL) free(log_file_name);
	if (pid_file_name != NULL) free(pid_file_name);

  return EXIT_SUCCESS;
}