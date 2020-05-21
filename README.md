# terraform-elb-to-alb

Transform your classic load balancers to application load balancer.

## What does it do
It takes your current terraform code with classic load balancers processes that code and outputs a new file to replace all of your classic load balancers with a single application load balancer. It does this in 3 stages.

### The Pre stage
In this stage it takes the directory containing your Terraform files, which will have the classic load balancers you want to transform in there, and processes those files in the following workflow:

- Finds all aws_elb resources and processes each resource in the following ways:

	- Apply any mappings that have been specified in the myMappings.txt file (more on this below)
	- Any local variables are replaced with a placeholder value, each mapping is placed in the mappings.txt file
	- Any data variables (where data is extracted from existing resources) are replaced with a placeholder value, again each mapping is placed in the mappings.txt file
	- Any other AWS resources references are replaced with a placeholder value, each mapping is then placed in the mappings.txt
	- Any variables are replaced with a placeholder value and the mappings are placed in mappings.txt
	- Any tags are replaces with a place holder value and the mappings are places in mappings.txt. Note that tags are currently not part of the output terraform files.

- Output the resulting resources into a single terraform file.
- Validate the new terraform file.
- Attempt to diagnose any validation issues. Note this currently happens but does not diagnose and fix any issues at present, as more testing is carried out new issues will present themselves to be automatically fixed.

### The Terraform plugin stage
In this stage we use the tool as a Terraform plugin. This lets us take advantage of all that terraform has to offer in terms of getting our files into a position for us to work with them. The plugin will take all of the resources parsed by terraform and create files for each of the necessary application load balancer subcomponents; target groups, listeners and listener rules for each of the resources, and attempt to extrapolate the values for these from the existing terraform code.

### The Post stage
In this stage we turn those placeholders back into the variable references they were before the pre stage so that it will pick up the correct values from the rest of your terraform code. We then output everything into a single lb.tf file which contains everything that is needed to replace you classic loadbalancers with application loadbalancers.

## So why would I want to do this
Many reasons, but the most important of them is cost, each classic loadbalancer costs around $21 per month. If you have an environment with 10 of those in thats $210 per month, if you have 10 environments that $2100 per month and that works out as over $25,000 a year which is a scary amount of money just for 1 component.

The other reasons:

  - Better health check monitoring; ELB's will send tcp packets to the specified port to check something responds, but just because somethings responds on that port doesn't mean that your application is actually up and running. ALB's allow you to specify a path the check as well as an expected http response code.
  - It breaks your load balancer configuration down into smaller more manageable and changeable chunks, if you make a change to an ELB the whole thing may need to be rebuilt or it might have a knock on affect on other components that reference it. Where as an ALB may just need a change to a single component protecting the whole of the load balancer configuration from being rebuilt and making it less likely that refering components will require rebuilding.

## I'm convinced how do I do it

You can either compile from source to get the executable or you can download the latest release.

Once you have the executable follow these instructions:

- Copy the executable to ~/.terraform.d/plugins/{architecture type}/ for example on mac os this would be ~/.terraform.d/plugins/darwin_amd64/
- Copy the executable to the parent directory of your terraform code.
- !!! Important !!! back up your terraform code directory, in case it doesn't go to plan.
- Run the Pre stage - ./terraform-plugin-elbtoalb -pre -tf_dir {terraform directory name}
- Once this is complete there should be a new directory called elbtoalb-output, in here is the output from the pre stage.
- Run the plugin stage -

	 - First as there is a new plugin you'll need to do a terraform init, so run terraform init elbtoalb-output
	 - If that succeeds then run the terraform apply - terraform apply elbtoalb-output
	 - You'll see the usual output from running a terraform apply, it should tell you what components are to be changed and the number of changes to be done, this should match the number of ELB's you have.
	 - Answer yes so the plugin can do it's magic.

- There should now be a new directory called lb_terraform, this directory contains all of the files for all of the new load balancer components. But they still currently have our placeholder values in, so...
- Run the Post stage - ./terraform-plugin-elbtoalb -post
- Once this is complete there will be a file lb_terraform/lb.tf that contains everything needed to create your new application load balancers, just pop it into your terraform code directory.

### What if it goes wrong
If you need to run the stages again for whatever reason you may need to tidy up before you can do so.

If the pre stage ran successfully then it will have updated some files in your terraform code, but its a good job you backed it up so you just need to restore the backup before proceeding.

If the plugin stage ran successfully it will have created a few files in elbtoalb-output, there are terraform.tfstate, mappings.txt and possible log.out if you have logging turned on for terraform. Remove these files particularly the terraform state file.

If the post stage ran successfully but you needed to make changes then you should be able to cleardown as above and rerun all of the stages.

## Is that is, really
No of course it isn't, take a look at the current limitations and assumptions. As well as that it may be that some other components need to be updated in order to integrate the new ALB's as certain components require different values depneding on whether you are pointing to an ELB or ALB, for example ASG's need a list of load balancer names when using ELB's but when using ALB's it needs a list of the target groups arn's to put its instances into. Or it could be that some of your applications don't like HTTP health check and were happy with the TCP ones in this case you may need to put something in place to allow the HTTP health check to work.

## Hold on you mentioned a myMappings.txt before, whats that about
The myMappings.txt allows you to set what certain things should be set to in the resulting terraform files, below is a list of the current know uses for the myMappings.txt. file.

| key | value | reason |
| --- | --- | --- |
| vpc_id | The value for your vpc_id or a variable that references your vpc id in your terraform code | ELB's do not reference the vpc which they are built in, but ALB's must reference it's VPC so in order to specify the correct vpc_id this value needs to be passed in. |

The file is laid out as key = value pairs.

## Sounds too good to be true, what limitations and assumptions are there

### Limitations
- ALB's can only support 5 security groups, so if your current ELB setup uses more than that it will try to add them all into the ALB and will through an error when you try to apply. To fix it you'll need to compact the number of security groups down to 5 or less.
- Tags are currently not in the output terraform files, you'll need to add these in manually.
- There may be instances where resource names end up longer than the max 32 characters, this is because the process to generate them is not able to take into account the length of variables, for example a name may work when its used in a "dev" environment but using it in "sandpit" may push the full length of the name over the 32 character limit.


### Assumptions
- Your code has been upgraded to use terraform 0.12.
- The AWS terraform plugin is at least version 2.40.
- The names of your ELB's can be used to generate the name of the host name filter on the listener rules, if not this may be something that needs to be updated after the tool is ran.
