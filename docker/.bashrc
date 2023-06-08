# Stoken
# # To refresh tokens:
# # Backup old stokenrc
# `cp ~/.stokenrc ~/.stokenrc.bak; rm ~/.stokenrc`
# # Import new token & remember not to enter a password at prompt
# `docker run -it -v /Users/smcquaid:/root stevemcquaid/stoken:latest stoken import --file=/root/.stoken/smcquaid_000700590089.sdtid`
# # If you do enter a password in previous step, unset it with this command
# `docker run -it -v /Users/smcquaid:/root stevemcquaid/stoken:latest stoken setpass`
# # Then run `stoken` to test
stoken() {
  docker run -it -v /Users/smcquaid:/root stevemcquaid/stoken:latest stoken
}
