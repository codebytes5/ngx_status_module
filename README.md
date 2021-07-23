
nginx mod status module

- compile:

	- cd to nginx source dir, run:

		export CFLAGS="-Wno-error=unused -O2"
		auto/configure --with-compat --add-dynamic-module='/path/to/ngx_mod_status' --add-dynamic-module='/path/to/ngx_mds_epoll' \
			--with-http_stub_status_module --with-threads

		make

	- add --with-debug for debugging

- module is found in objs dir, the files are ngx_mds_epoll.so and ngx_mod_status.so, include both files, in nginx configuration
	
	i.e: nginx.conf

		load_module /path/to/ngx_mds_epoll.so;
		load_module /path/to/ngx_mod_status.so;

- edit nginx.conf to load module:

		events {
			use mds_epoll;
		}

		location = /basic_status {
			ngx_mds;
			ngx_mds_msg_size 500; # >= 500, maximum number of characters on one line in results
			ngx_mds_msg_count 20; # >= 5, maximum number of lines per process in results
		}

        location / {
        	# path to .js file 
            root /path/to/js_file;
            index  index.html index.htm;
        }

- ngx_mds_epoll.so is optional, if used enable it int events configuration as bellow: 
	
		events {
			use mds_epoll;
		}

- edit js file and change script_name variable if location = /basic_status is changed

- tuning:

	- adjust refresh variable in js file higher or lower than 500, then adjust browser refresh variable, it should be double the size
		of the js variable, thus arround 1000
		
		i.e: 
			browser: /basic_status?refresh=1000
			ngx_mod_status.js: var refresh = 500;
	
	- activate experimental lingering scan by using expl variable in browser
	
		i.e:
			browser turn on expl: /basic_status?expl=1
			browser turn off expl: /basic_status?expl=0
			
	- combine tuning variables
	
		i.e:
			browser: /basic_status?refresh=1000&expl=0

- tested with nginx 1.20.0

