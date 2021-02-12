# Venafi Provider Examples

In this section you'll find examples to make your implementation of your venafi provider for automating your process of SSL integration in your infrastructure.

>Before doing so, you want to make sure you have [terraform properly installed](#terraform-installation).

**Examples:**

- [SSL Termination with F5 BIG-IP](./f5_example/README.md)

## Terraform installation

> **_Note:_**  We highly recommend to use a Unix based OS in order to use our tools.

To install terraform first, download the apropiate package for you system here: https://www.terraform.io/downloads.html.

#### Windows

Do as follows:

1. Go to **Control Panel** -> **System** -> **System settings** -> **Environment Variables**.
2. Scroll down in system variables until you find **PATH**.
3. Click **edit** and change accordingly.
4. BE SURE to include a semicolon at the end of the previous as that is the delimiter, i.e. c:\path;c:\path2
Launch a new console for the settings to take effect.

#### WSL

Open your WSL terminal in the folder where you downloaded your `.zip` file, then execute the following:

```BASH
$ unzip <your_terraform_zip>.zip
$ sudo mv <your_terraform_file> /usr/local/bin # it should be named "terraform"
$ rm <your_terraform_zip>.zip
```

#### Linux

Open your terminal in the folder where you have your `.zip` file, then execute the following:

```BASH
$ unzip <your_terraform_zip>.zip
$ sudo mv <your_terraform_file> /usr/local/bin # it should be named "terraform"
$ rm <your_terraform_zip>.zip
```

Run the following command to verify terraform is installed.
```
terraform -v
```