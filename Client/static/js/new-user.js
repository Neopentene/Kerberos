
window.onload = () => {

    keyDigest = {
        ASPublicKey: "",
        TGSPublicKey: "",
        ServerPublicKey: ""
    }

    let loginFormCopy = {
        "formParent": document.getElementById('new-user-form').parentElement,
        "originalForm": document.getElementById('new-user-form')
    }

    let flowCounter = 0
    let semaphor = 0

    let userDetails = {
        username: "",
        password: "",
        enc_username: "",
        enc_password: "",
        timestamp: "",
        nonce: ""
    }

    let flowGraph = [
        {
            method: async function () {
                updateTextContent("status", "Initializing Service")
                updateTextContent("status-body", "")
                await sleep(2000)

                updateTextContent("status", "Done")
                return true
            },
            nextButtonName: "Start",
        },
        {
            method: async function () {
                updateTextContent("status", "Getting Public Key of Service Server")
                updateTextContent("status-body", "")
                await sleep(2000)

                let key = await fetch('/api/Service/public/key').then(res => {
                    if (res.status === 200) {
                        return res.json()
                    }
                    return undefined
                }).catch(() => {
                    return undefined
                })

                if (key === undefined) {
                    updateTextContent("status", "Error... Couldn't Find the Public Key")
                    return false
                }

                updateTextContent("status", "Service Server Public Key Received")
                updateTextContent("status-body", "Public Key: " + key.public_key)
                return true
            },
            nextButtonName: "Get Server Public Key",
        },
        {
            // get AS address
            method: async function () {
                updateTextContent("status", "Encrypting Username and Password for Transport")
                updateTextContent("status-body", "")
                await sleep(2000)

                let encrypted = await fetch(
                    "/api/encrypt/service/details?username="
                    + userDetails.username
                    + "&password=" + userDetails.password, {

                }).then(res => {
                    if (res.status === 200) {
                        return res.json()
                    }
                    return undefined
                }).catch(() => {
                    return undefined
                })

                if (encrypted === undefined) {
                    updateTextContent("status", "Error... Couldn't Encrypt the Userdetails")
                    return false
                }

                userDetails.enc_username = encrypted.username
                userDetails.enc_password = encrypted.password


                updateTextContent("status-body", "Encrypted Data: " + userDetails.enc_username + userDetails.enc_username)
                return true
            },

            nextButtonName: "Encrypt User Details"
        },
        {
            method: async function () {
                updateTextContent("status", "Sending New User Details to Service Server")
                updateTextContent("status-body", "")
                await sleep(2000)

                let timestamp = await fetch("/api/service/validate/user")
                    .then(res => {
                        if (res.status === 200) {
                            return res.json()
                        }
                        return undefined
                    }).catch((error) => {
                        return undefined
                    })

                if (timestamp === undefined) {
                    updateTextContent("status", "Error Couldn't Validate User")
                    return false
                }

                userDetails.timestamp = timestamp.timestamp
                userDetails.nonce = timestamp.nonce

                updateTextContent("status", "User Validated")
                updateTextContent("status-body", "Timestamp Received: " + timestamp.timestamp)
                return true
            },
            nextButtonName: "Authenticate to Server"
        },
        {
            method: async function () {
                updateTextContent("status", "Sending New User Details to Service Server")
                updateTextContent("status-body", "")
                await sleep(2000)

                let status = await fetch("/api/service/new/user/" + userDetails.timestamp, {
                    method: 'POST', // or 'PUT'
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        username: userDetails.enc_username,
                        password: userDetails.enc_password,
                        nonce: userDetails.nonce
                    })
                }).then(res => {
                    if (res.status === 200) {
                        return res.json()
                    }
                    return undefined
                }).catch((error) => {
                    return undefined
                })

                if (status === undefined || status.success === false) {
                    updateTextContent("status", "Error Couldn't Create new User")
                    return false
                }

                updateTextContent("status", "User Created")
                updateTextContent("status-body", "Username: " + encrypted_username)
                return true
            },
            nextButtonName: "Create User"
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
        previousData.formParent.appendChild(previousData.originalForm)
        addEvents()
    }

    function addEvents() {
        eventSubmitForm("new-user-form", ["username", "password"])
        eventTogglePasswordInputType("toggle-password-field-label", "password")
    }

    function addNewKerberosFlowEvent() {
        flowCounter = 0
        updateTextContent("status-body", "")
        updateTextContent("status", "Start Creation of New User")

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
        loginFormCopy = collapseForm("new-user-form")

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