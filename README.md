
## Install
```
npm install serverless -g

npm install
```

Modify `servelrss.yml`
Update the `environment` section with your values and `region:` to match where your WAF is
```
  environment:
    WebACL_ID: 2c39d8e7-1b8c-4a3d-9f03-ebf123274e9d
    MAX_REQUESTS_PER_IP: 200
```

**MAX_REQUESTS_PER_IP**:
This value is per **5 min** as logs get generated every 5 min.

Say X is that required maximum load for the application
`0 < Light Load < X/2 < Regular Load < 2X/3 < High Load < X <= Heavy Load`


## Deployment
```
npm install --only prod
AWS_PROFILE=YOUR_AWS_PROFILE  sls deploy
npm install
```

## AWS Config
Set up a trigger for this function, from S3 bucket where ALB logs are stored. Dont forget to user Prefix if its stored in a "sub directory" of a bucket


## Testing
To see how this reacts to the load, use  [siege](https://linux.die.net/man/1/siege)