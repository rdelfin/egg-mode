//! Infrastructure types related to packaging rate-limit information alongside responses from
//! Twitter.

use crate::error::Error::{self, *};
use crate::error::{Result, TwitterErrors};

use hyper::client::{HttpConnector, ResponseFuture};
use hyper::{self, Body, Request, Uri};
use hyper_proxy::{Intercept, Proxy, ProxyConnector};
#[cfg(feature = "hyper-rustls")]
use hyper_rustls::HttpsConnector;
#[cfg(feature = "native_tls")]
use hyper_tls::{
    native_tls::{Identity, TlsConnector},
    HttpsConnector,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json;
#[cfg(feature = "native_tls")]
use tokio_tls;

use std::convert::TryFrom;
use std::env;
use std::fs::File;
use std::io::Read;

use super::Headers;

const X_RATE_LIMIT_LIMIT: &'static str = "X-Rate-Limit-Limit";
const X_RATE_LIMIT_REMAINING: &'static str = "X-Rate-Limit-Remaining";
const X_RATE_LIMIT_RESET: &'static str = "X-Rate-Limit-Reset";
const IDENTITY_CERT_ENVVAR: &'static str = "EGGMODE_IDENTITY_CERT";
const IDENTITY_PASS_ENVVAR: &'static str = "EGGMODE_IDENTITY_PASSWORD";
const PROXY_ENVVAR: &'static str = "EGGMODE_PROXY";

fn rate_limit(headers: &Headers, header: &'static str) -> Result<Option<i32>> {
    let val = headers.get(header);

    if let Some(val) = val {
        let val = val.to_str()?.parse::<i32>()?;
        Ok(Some(val))
    } else {
        Ok(None)
    }
}

fn rate_limit_limit(headers: &Headers) -> Result<Option<i32>> {
    rate_limit(headers, X_RATE_LIMIT_LIMIT)
}

fn rate_limit_remaining(headers: &Headers) -> Result<Option<i32>> {
    rate_limit(headers, X_RATE_LIMIT_REMAINING)
}

fn rate_limit_reset(headers: &Headers) -> Result<Option<i32>> {
    rate_limit(headers, X_RATE_LIMIT_RESET)
}

fn empty_str_to_opt(s: String) -> Option<String> {
    if s == "" {
        None
    } else {
        Some(s)
    }
}

fn get_proxy() -> Option<Proxy> {
    empty_str_to_opt(env::var(PROXY_ENVVAR).unwrap_or("".to_string()))
        .map(|proxy_str| proxy_str.parse::<Uri>().unwrap())
        .map(|uri| Proxy::new(Intercept::All, uri.clone()))
}

// Native TLS supports passing down a proxy and identity
#[cfg(feature = "native_tls")]
fn get_response_impl(mut request: Request<Body>) -> ResponseFuture {
    let proxy = get_proxy();
    let identity = get_identity();

    let connector = match identity {
        Some(identity) => HttpsConnector::from((
            HttpConnector::new(),
            tokio_tls::TlsConnector::from(
                TlsConnector::builder().identity(identity).build().unwrap(),
            ),
        )),
        None => HttpsConnector::new(),
    };

    match proxy {
        Some(proxy) => {
            let proxy_uri = proxy.uri().clone();
            let proxy_connector = ProxyConnector::from_proxy(connector, proxy).unwrap();
            if let Some(headers) = proxy_connector.http_headers(&proxy_uri) {
                request.headers_mut().extend(headers.clone().into_iter());
            }
            let client = hyper::Client::builder().build(proxy_connector);
            client.request(request)
        }
        None => {
            let client = hyper::Client::builder().build(connector);
            client.request(request)
        }
    }
}

#[cfg(not(feature = "native_tls"))]
fn get_response_impl(mut request: Request<Body>) -> ResponseFuture {
    let client = hyper::client::builder().build(connector);
    client.request(request)
}

#[cfg(feature = "native_tls")]
fn get_identity() -> Option<Identity> {
    let identity_path = empty_str_to_opt(env::var(IDENTITY_CERT_ENVVAR).unwrap_or("".to_string()));
    let identity_password =
        empty_str_to_opt(env::var(IDENTITY_PASS_ENVVAR).unwrap_or("".to_string()));

    let identity = identity_path.and_then(|path| identity_password.map(|pass| (path, pass)));

    match identity {
        Some((path, password)) => {
            let mut file = File::open(path).unwrap();
            let mut identity = vec![];
            file.read_to_end(&mut identity).unwrap();
            Some(Identity::from_pkcs12(&identity, &password).unwrap())
        }
        None => None,
    }
}

// n.b. this type is re-exported at the crate root - these docs are public!
///A helper struct to wrap response data with accompanying rate limit information.
///
///This is returned by any function that calls a rate-limited method on Twitter, to allow for
///inline checking of the rate-limit information without an extra call to
///`service::rate_limit_info`.
///
///As this implements `Deref` and `DerefMut`, you can transparently use the contained `response`'s
///methods as if they were methods on this struct.
#[derive(
    Debug, Deserialize, derive_more::Constructor, derive_more::Deref, derive_more::DerefMut,
)]
pub struct Response<T> {
    /// The latest rate-limit information returned with the request.
    #[serde(flatten)]
    pub rate_limit_status: RateLimit,
    /// The decoded response from the request.
    #[deref]
    #[deref_mut]
    #[serde(default)]
    pub response: T,
}

impl<T> Response<T> {
    ///Convert a `Response<T>` to a `Response<U>` by running its contained response through the
    ///given function. This preserves its rate-limit information.
    ///
    ///Note that this is not a member function, so as to not conflict with potential methods on the
    ///contained `T`.
    pub fn map<F, U>(src: Response<T>, fun: F) -> Response<U>
    where
        F: FnOnce(T) -> U,
    {
        Response {
            rate_limit_status: src.rate_limit_status,
            response: fun(src.response),
        }
    }

    ///Attempt to convert a `Response<T>` into a `Response<U>` by running its contained response
    ///through the given function, preserving its rate-limit information. If the conversion
    ///function fails, an error is returned instead.
    ///
    ///Note that this is not a member function, so as to not conflict with potential methods on the
    ///contained `T`.
    pub fn try_map<F, U, E>(src: Response<T>, fun: F) -> std::result::Result<Response<U>, E>
    where
        F: FnOnce(T) -> std::result::Result<U, E>,
    {
        Ok(Response {
            rate_limit_status: src.rate_limit_status,
            response: fun(src.response)?,
        })
    }

    /// Converts a `Response<T>` into a `Response<U>` using the `Into` trait.
    ///
    /// This is implemented as a type function instead of the `From`/`Into` trait due to
    /// implementation conflicts with the `From<T> for T` implementation in the standard library.
    /// It is also implemented as a function directly on the `Response` type instead of as a member
    /// function to not clash with the `into()` function that would be available on the contained
    /// `T`.
    pub fn into<U>(src: Self) -> Response<U>
    where
        T: Into<U>,
    {
        Response {
            rate_limit_status: src.rate_limit_status,
            response: src.response.into(),
        }
    }
}

impl<T: IntoIterator> IntoIterator for Response<T> {
    type IntoIter = ResponseIter<T::IntoIter>;
    type Item = Response<T::Item>;

    fn into_iter(self) -> Self::IntoIter {
        ResponseIter {
            it: Response::map(self, |it| it.into_iter()),
        }
    }
}

/// Iterator wrapper around a `Response`.
///
/// This type is returned by `Response`'s `IntoIterator` implementation. It uses the `IntoIterator`
/// implementation of the contained `T`, and copies the rate-limit information to yield individual
/// `Response<T::Item>` instances.
pub struct ResponseIter<T> {
    it: Response<T>,
}

impl<T: Iterator> Iterator for ResponseIter<T> {
    type Item = Response<T::Item>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(Response {
            rate_limit_status: self.it.rate_limit_status,
            response: self.it.response.next()?,
        })
    }
}

// n.b. this function is re-exported in the `raw` module - these docs are public!
/// Converts the given request into a raw `ResponseFuture` from hyper.
pub fn get_response(request: Request<Body>) -> ResponseFuture {
    get_response_impl(request)
}

// n.b. this function is re-exported in the `raw` module - these docs are public!
/// Loads the given request, parses the headers and response for potential errors given by Twitter,
/// and returns the headers and raw bytes returned from the response.
pub async fn raw_request(request: Request<Body>) -> Result<(Headers, Vec<u8>)> {
    let resp = get_response(request).await?;
    let (parts, body) = resp.into_parts();
    let body: Vec<_> = hyper::body::to_bytes(body).await?.to_vec();
    if let Ok(errors) = serde_json::from_slice::<TwitterErrors>(&body) {
        if errors.errors.iter().any(|e| e.code == 88)
            && parts.headers.contains_key(X_RATE_LIMIT_RESET)
        {
            return Err(RateLimit(rate_limit_reset(&parts.headers)?.unwrap()));
        } else {
            return Err(TwitterError(parts.headers, errors));
        }
    }
    if !parts.status.is_success() {
        return Err(BadStatus(parts.status));
    }
    Ok((parts.headers, body))
}

// n.b. this function is re-exported in the `raw` module - these docs are public!
/// Loads the given request and discards the response body after parsing it for rate-limit and
/// error information, returning the rate-limit information from the headers.
pub async fn request_with_empty_response(request: Request<Body>) -> Result<Response<()>> {
    let (headers, _) = raw_request(request).await?;
    let rate_limit_status = RateLimit::try_from(&headers)?;
    Ok(Response {
        rate_limit_status,
        response: (),
    })
}

// n.b. this function is re-exported in the `raw` module - these docs are public!
/// Loads the given request and parses the response as JSON into the given type, including
/// rate-limit headers.
pub async fn request_with_json_response<T: DeserializeOwned>(
    request: Request<Body>,
) -> Result<Response<T>> {
    let (headers, body) = raw_request(request).await?;
    let response = serde_json::from_slice(&body)?;
    let rate_limit_status = RateLimit::try_from(&headers)?;
    Ok(Response {
        rate_limit_status,
        response,
    })
}

// n.b. this type is exported at the crate root - these docs are public!
/// Rate limit information returned with a `Response`.
///
/// With every API call, Twitter returns information about how many times you're allowed to call
/// that endpoint, and at what point your limit refreshes and allows you to call it more. These are
/// normally passed through the response headers, and egg-mode reads for these headers when a
/// function returns a `Response<T>`. If the headers are absent for a given request, the field will
/// be `-1`.
///
/// Rate limits are tracked separately based on the kind of `Token` you're using. For Bearer tokens
/// using Application-only authentication, the rate limit is based on your application as a whole,
/// regardless of how many instances are using that token. For Access tokens, the rate limit is
/// broken down by-user, so more-active users will not use up the rate limit for less-active ones.
///
/// For more information about rate-limiting, see [Twitter's documentation about rate
/// limits][rate-limit].
///
/// [rate-limit]: https://developer.twitter.com/en/docs/basics/rate-limiting
#[derive(Copy, Clone, Debug, Deserialize)]
pub struct RateLimit {
    /// The rate limit ceiling for the given request.
    pub limit: i32,
    /// The number of requests left for the 15-minute window.
    pub remaining: i32,
    /// The UTC Unix timestamp at which the rate window resets.
    pub reset: i32,
}

impl TryFrom<&Headers> for RateLimit {
    type Error = Error;
    fn try_from(headers: &Headers) -> Result<Self> {
        Ok(Self {
            limit: rate_limit_limit(headers)?.unwrap_or(-1),
            remaining: rate_limit_remaining(headers)?.unwrap_or(-1),
            reset: rate_limit_reset(headers)?.unwrap_or(-1),
        })
    }
}
