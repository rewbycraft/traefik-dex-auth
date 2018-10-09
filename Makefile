all:
	 docker build -t traefik-dex-auth --network host --rm .
