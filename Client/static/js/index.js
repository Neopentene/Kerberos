
window.onload = () => {

    keyDigest = {
        ASPublicKey: "",
        TGSPublicKey: "",
        ServerPublicKey: ""
    }

    let loginFormCopy = {
        "formParent": document.getElementById('login-form').parentElement,
        "originalForm": document.getElementById('login-form')
    }

    let flowCounter = 0
    let semaphor = 0

    let userDetails = {
        username: "",
        password: "",
        encrypted_username: ""
    }

    let flowGraph = [
        {
            method: async function () {
                updateTextContent("status", "Initializing Kerberos")
                updateTextContent("status-body", "")
                await fetch('/')
                await sleep(2000)

                updateTextContent("status", "Done")
                return true
            },
            nextButtonName: "Start",
        },
        {
            // get AS address
            method: async function () {
                updateTextContent("status", "Requesting Authentication Server Address")
                updateTextContent("status-body", "")
                await sleep(2000)

                let address = await fetch("/api/AS/host").then(res => {
                    if (res.status === 200) {
                        return res.text()
                    }
                    return undefined
                }).catch(() => {
                    return undefined
                })

                if (address === undefined) {
                    updateTextContent("status", "Error... Couldn't Find the Address")
                    return false
                }

                updateTextContent("status", "Address Found")
                updateTextContent("status-body", "Server at " + address)
                return true
            },
            nextButtonName: "Get AS Address"
        },
        {
            // get AS public key
            method: async function () {
                updateTextContent("status", "Requesting Authentication Server Public Key")
                updateTextContent("status-body", "")
                await sleep(2000)

                let key = await fetch("/api/AS/public/key").then(res => {
                    if (res.status === 200) {
                        return res.json()
                    }
                    return undefined
                }).catch(() => {
                    return undefined
                })

                if (key === undefined) {
                    updateTextContent("status", "Error... Public Key Not Found")
                    return false
                }

                updateTextContent("status", "AS Public Key Received")
                updateTextContent("status-body", "Public Key: " + key.public_key)
                return true
            },
            nextButtonName: "Get AS Public Key"
        },
        {
            // encrypt username using public key
            method: async function () {
                updateTextContent("status", "Encrypting Username")
                updateTextContent("status-body", "")
                await sleep(2000)

                let encrypted_username = await fetch("/api/encrypt/user/" + userDetails.username)
                    .then(res => {
                        if (res.status === 200) {
                            return res.text()
                        }
                        return undefined
                    }).catch((error) => {
                        return undefined
                    })

                if (encrypted_username === undefined) {
                    updateTextContent("status", "Error Couldn't Encrypt Username")
                    return false
                }
                userDetails.encrypted_username = encrypted_username

                updateTextContent("status", "Encrypting Username Successful")
                updateTextContent("status-body", "Username: " + encrypted_username)
                return true
            },
            nextButtonName: "Encrypt Username"
        },
        {
            // send username to authentication server
            method: async function () {
                updateTextContent("status", "Sending Username to AS")
                updateTextContent("status-body", "")
                await sleep(2000)

                updateTextContent("status", "Getting TGT from AS")
                await sleep(2000)

                let tgt = await fetch("/api/AS/tgt/" + userDetails.encrypted_username)
                    .then(res => {
                        if (res.status === 200) {

                            return res.json()
                        }
                        return undefined
                    }).catch(() => {
                        return undefined
                    })

                if (tgt === undefined) {
                    updateTextContent("status", "Error... Couldn't Authenticate User")
                    return false
                }
                updateTextContent("status", "TGT Was Obtained")
                updateTextContent("status-body", "TGT: " + tgt.tgt)
                return true
            },
            nextButtonName: "Get TGT"
        },
        {
            // decrypt tgt session key
            method: async function () {
                updateTextContent("status", "Coverting Password Into Key")
                updateTextContent("status-body", "")
                await sleep(2000)

                updateTextContent("status", "Decrypting TGT Session")
                await sleep(2000)

                let tgt = await fetch("/api/decrypt/tgt/session/" + userDetails.password)
                    .then(res => {
                        if (res.status === 200) {
                            return res.json()
                        }
                        return undefined
                    }).catch((error) => {
                        return undefined
                    })


                if (tgt === undefined) {
                    updateTextContent("status", "Error... Couldn't Decrypt TGT Session")
                    return false
                }
                updateTextContent("status", "TGS Session Id was Decrypted")
                updateTextContent("status-body", "Decrypted Session: " + tgt.session)
                return true
            },
            nextButtonName: "Decrypt TGS Session"
        },
        {
            // get TGS address
            method: async function () {
                updateTextContent("status", "Requesting TGS Address")
                updateTextContent("status-body", "")
                await sleep(2000)

                let address = await fetch("/api/TGS/host").then(res => {
                    if (res.status === 200) {
                        return res.text()
                    }
                    return undefined
                }).catch(() => {
                    return undefined
                })

                if (address === undefined) {
                    updateTextContent("status", "Error... Couldn't Find the Address")
                    return false
                }

                updateTextContent("status", "Address Found")
                updateTextContent("status-body", "Server at " + address)
                return true
            },
            nextButtonName: "Get TGS Address"
        },
        {
            // get TGS public key
            method: async function () {
                updateTextContent("status", "Requesting TGS Public Key")
                updateTextContent("status-body", "")
                await sleep(2000)

                let key = await fetch("/api/TGS/public/key").then(res => {
                    if (res.status === 200) {
                        return res.json()
                    }
                    return undefined
                }).catch(() => {
                    return undefined
                })

                if (key === undefined) {
                    updateTextContent("status", "Error... Public Key not Found")
                    return false
                }

                updateTextContent("status", "TGS Public Key Received")
                updateTextContent("status-body", "Public Key: " + key.public_key)
                return true
            },
            nextButtonName: "Get TGS Public Key"
        },
        {
            // get ticket from TGS
            method: async function () {
                updateTextContent("status", "Sending TGT To TGS With Encoded Client Info")
                updateTextContent("status-body", "")
                await sleep(2000)

                updateTextContent("status", "Getting Ticket From TGS")
                await sleep(2000)

                let ticket = await fetch("/api/TGS/ticket/" + userDetails.username)
                    .then(res => {
                        if (res.status === 200) {
                            return res.text()
                        }
                        return undefined
                    }).catch(() => {
                        return undefined
                    })

                if (ticket === undefined) {
                    updateTextContent("status", "Error... Failed To Get Ticket")
                    return false
                }
                updateTextContent("status", "Ticket Was Obtained")
                updateTextContent("status-body", "Ticket: " + ticket)
                return true
            },
            nextButtonName: "Get Server Ticket"
        },
        {
            // Decrypting Server Session
            method: async function () {
                updateTextContent("status", "Getting TGS Session")
                updateTextContent("status-body", "")
                await sleep(2000)

                updateTextContent("status", "Decrypting Server Session")
                await sleep(2000)

                let server_session = await fetch("/api/decrypt/server/session")
                    .then(res => {
                        if (res.status === 200) {
                            return res.json()
                        }
                        return undefined
                    }).catch((error) => {
                        return undefined
                    })


                if (server_session === undefined) {
                    updateTextContent("status", "Error... Couldn't Decrypt TGT Session")
                    return false
                }

                console.log(server_session)

                updateTextContent("status", "Server Session Id was Decrypted")
                updateTextContent("status-body", "Decrypted Session: " + server_session.server_session)
                return true
            },
            nextButtonName: "Decrypt Server Session"
        },
        {
            method: async function () {
                updateTextContent("status", "Setting Up Service...")
                updateTextContent("status-body", "")
                await sleep(2000)

                let button = document.getElementById("status-update")
                let buttonParent = button.parentElement
                let redirectButton = button.cloneNode(false)

                redirectButton.id = "redirect"
                redirectButton.textContent = "Redirect"
                redirectButton.addEventListener("click", () => {
                    let a = document.createElement("a")
                    a.href = "/service"
                    a.click()
                })

                buttonParent.insertBefore(redirectButton, button)

                updateTextContent("status", "Service Setup Complete")
                updateTextContent("status-body", "")
                await (2000)

                updateTextContent("status", "Click on Redirect to Access the Service")
                updateTextContent("status-body", "Click on Reset to Revert and Free Service")

                return true
            },
            nextButtonName: "Request Service"
        },
        {
            method: async function () {
                updateTextContent("status", "Resetting Form")
                updateTextContent("status-body", "")
                await sleep(2000)

                revertInitialization(loginFormCopy)

                return false
            },
            nextButtonName: "Reset"
        }

    ]

    function sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    function switchDataType(targetId = "") {
        let target = document.getElementById(targetId)
        let currentAttributeValue = target.getAttribute("data-type")

        if (currentAttributeValue === "invisible") {
            target.setAttribute('data-type', 'visible');
        } else {
            target.setAttribute('data-type', 'invisible');
        }
    }

    function updateTextContent(targetId = "", text = "") {
        let target = document.getElementById(targetId)
        target.textContent = text
    }

    function collapseForm(formId) {
        let form = document.getElementById(formId)
        let originalForm = form.cloneNode(true)
        let formParent = form.parentElement
        form.style.opacity = "0"

        setTimeout(() => {
            formParent.removeChild(form)
        }, 400)

        return { "formParent": formParent, "originalForm": originalForm }
    }

    function eventTogglePasswordInputType(elementId = "", targetId = "") {
        let element = document.getElementById(elementId)
        let target = document.getElementById(targetId)

        element.addEventListener("click", () => {
            let currentType = target.type
            if (currentType === "password") {
                target.type = "text"
            } else {
                target.type = "password"
            }
        })
    }

    function eventSubmitForm(formId = "", validateIds = []) {

        let form = document.getElementById(formId)

        let elements = validateIds.map((id) => {
            return document.getElementById(id)
        })

        form.addEventListener("submit", (event) => {

            event.preventDefault()

            for (let element of elements) {
                if (element.value === "") {
                    element.focus()
                    return
                }
            }

            for (id of validateIds) {
                userDetails[id] = document.getElementById(id).value
            }

            initializeKerberos()
        })
    }

    function revertInitialization(previousData =
        {
            "formParent": document.createElement('section'),
            "originalForm": document.createElement('form')
        }
    ) {
        switchDataType("status-container")
        try {
            let button = document.getElementById("redirect")
            button.parentElement.removeChild(button)
        } catch (error) {

        }
        previousData.formParent.appendChild(previousData.originalForm)
        addEvents()
    }

    function addEvents() {
        eventSubmitForm("login-form", ["username", "password"])
        eventTogglePasswordInputType("toggle-password-field-label", "password")
    }

    function addNewKerberosFlowEvent() {
        flowCounter = 0
        updateTextContent("status-body", "")
        updateTextContent("status", "Start Kerberos Authentication")

        let originalflowButton = document.getElementById("status-update")
        let flowButtonParent = originalflowButton.parentElement
        let flowButton = originalflowButton.cloneNode(false)
        flowButtonParent.replaceChild(flowButton, originalflowButton)

        async function flowGraphEvents(event) {

            if (semaphor++ < 1) {

                switchDataType("loading-inactive")
                switchDataType("loading-active")
                let success = await flowGraph[flowCounter].method()

                if (success && flowCounter < flowGraph.length - 1) {
                    flowCounter++
                } else {
                    flowCounter = flowGraph.length - 1
                }
                switchDataType("loading-inactive")
                switchDataType("loading-active")
                flowButton.textContent = flowGraph[flowCounter].nextButtonName

                semaphor = 0
            }
        }

        flowButton.textContent = flowGraph[flowCounter].nextButtonName

        flowButton.addEventListener("click", flowGraphEvents)
    }

    async function initializeKerberos() {
        loginFormCopy = collapseForm("login-form")

        await sleep(400)
        switchDataType("status-container")
        addNewKerberosFlowEvent()
    }

    /*

    async function initializeKerberos() {
        let revert = collapseForm("login-form")

        await sleep(400)
        switchDataType("status-container")

        await sleep(300)
        updateTextContent("status", "Getting the Authentication Server's address")
        await sleep(1000)

        let ASDomain = await fetch("/api/AS/host").then((response) => {
            return response.text
        }).catch((error) => {
            return undefined
        })

        if (ASDomain === undefined) {
            updateTextContent("status", "Error getting the Authentication Server's address")
            await sleep(1000)

            updateTextContent("status", "Reverting...")
            await sleep(1000)

            revertInitialization(revert)

            return
        } else {
            updateTextContent("status", "Error getting the Authentication Server's address")
            await sleep(1000)
        }

        await sleep(300)
        updateTextContent("status", "Getting the Authentication Server's public key")
        await sleep(500)

        let publickey = await fetch("/api/public/key").then((response) => {
            return response.json()
        })


        await sleep(1000)
        console.log(publickey)
        revertInitialization(revert);
    }
    */

    addEvents()
}