from tornado.httpclient import AsyncHTTPClient, HTTPClientError, HTTPError
from tornado.web import RequestHandler, Application
from tornado.ioloop import IOLoop
from urllib.parse import urljoin, urlparse, urlunparse, urlencode
import poster
from tornado.log import app_log, enable_pretty_logging
import sys
import ujson


NPM_REGISTRY_URL = 'https://registry.npmjs.org/'
SERVER_NETLOC = 'localhost:8081'
IPFS_API_URL = 'http://127.0.0.1:5001/api/v0/'
IPFS_GW_URL = 'http://127.0.0.1:8080/ipfs/'


def rewrite_version(version_manifest):
    tarball_url = urlparse(version_manifest['dist']['tarball'])
    version_manifest['tarball'] = urlunparse((tarball_url.scheme, SERVER_NETLOC, tarball_url.path, None, None, None))
    return version_manifest


def rewrite_urls(package_manifest_str):
    package_manifest = ujson.loads(package_manifest_str)
    package_manifest['versions'] = {version: rewrite_version(manifest) for version, manifest in package_manifest['versions'].items()}
    return ujson.dumps(package_manifest)


class NPMProxyHandler(RequestHandler):
    async def proxy(self):
        client = AsyncHTTPClient()
        try:
            resp = await client.fetch(urljoin(NPM_REGISTRY_URL, self.request.path),
                method=self.request.method, body=self.request.body, headers=self.request.headers, 
                follow_redirects=False, raise_error=True)
        except HTTPClientError as err:
            self.set_status(err.code)
            self.finish(err.response.body)
            return
        except Exception as err:
            app_log.warning('Error connecting to npm', exc_info=sys.exc_info)
            self.send_error(503)
            return
        # TODO: stream instead of bufferring
        self.finish(resp.body)

    post = proxy
    get = proxy
    put = proxy


class NPMPackageManifestHandler(RequestHandler):
    async def get(self, package):
        client = AsyncHTTPClient()
        try:
            resp = await client.fetch(urljoin(NPM_REGISTRY_URL, self.request.path))
        except HTTPClientError as err:
            self.set_status(err.code, err.response)
            self.finish()
            return
        except Exception as err:
            app_log.warn('Error connecting to npm', exc_info=sys.exc_info)
            self.set_status(503, 'Service unavailable')
            self.finish()
            return
        # TODO: stream instead of bufferring
        self.finish(rewrite_urls(resp.body))
        

class NPMTarballHandler(RequestHandler):
    def initialize(self, lookup):
        self.lookup = lookup

    async def get(self, package, tarball):
        if tarball in lookup:
            app_log.info('tarball found in lookup table')
        else:
            app_log.info('Downloading file from npm and adding to ipfs')
            client = AsyncHTTPClient()
            tarball_resp = await client.fetch(urljoin(NPM_REGISTRY_URL, self.request.path))
            ipfs_hash = await self.ipfs_add(tarball_resp.body, tarball)
            lookup[tarball] = ipfs_hash
        self.redirect(urljoin(IPFS_GW_URL, lookup[tarball]), True)

    async def ipfs_add(self, tarball, tarball_name):
        client = AsyncHTTPClient()
        message, headers = poster.encode.multipart_encode({tarball_name: tarball})
        payload = b''.join(chunk.encode() for chunk in message if type(chunk) == str)
        resp = await client.fetch(urljoin(IPFS_API_URL, 'add' + '?' +  urlencode({'path': tarball})), body=payload, headers=headers, method='POST')
        return ujson.loads(resp.body)['Hash']
    

lookup = dict()

app = Application([
    (r'/(\w+)', NPMPackageManifestHandler),
    (r'/(\w+)/-/([\w.-]+.tgz)', NPMTarballHandler, {'lookup': lookup}),
    (r'/.*', NPMProxyHandler)
])

if __name__ == '__main__':
    enable_pretty_logging()
    app.listen((8081))
    IOLoop.current().start()