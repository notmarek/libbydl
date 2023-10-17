# LibbyDL
a "simple" OverDrive ebook downloader

# Usage

```
1. you will need a library card with access to OverDrive
2. open Libby either on your phone or on https://libbyapp.com 
3. login with your card into it as you would normally
4. go to settings > copy to another device then run "python -m LibbyDL clone {the code you got in libby}"
5. run "python -m LibbyDL provision-ade-account" so you can actually decrypt the ebooks
6. have fun!
```

# API notes
### Managing loans and accounts
sentry-read.svc.overdrive.com

read.svc.overdrive.com // seems to work as well 

### Tagging
vandal.svc.overdrive.com

### Search
thunder.overdrive.com

autocomplete.api.overdrive.com

### CDN
thunder.cdn.overdrive.com

images.overdrive.com

images.cdn.overdrive.com

### Samples
samples.overdrive.com

### Library services
ntc.api.overdrive.com

### Main app + logging
libbyapp.com

### js libraries
bflat.read.libbyshelf.com

bflat.listen.libbyshelf.com


### in-app reading
dewey-{some kind of uuid - probably of the node}.read.libbyshelf.com

### Error Logging
sage.svc.overdrive.com