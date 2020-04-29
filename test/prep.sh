cd .. 
cp terraform-provider-elbtoalb ~/.terraform.d/plugins/darwin_amd64/
cd -
export TF_LOG_PATH=./log.out
export TF_LOG=trace
rm log.out || true
rm terraform.tfstate || true 
terraform init

