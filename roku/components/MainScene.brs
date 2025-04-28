Sub Init()
    m.top.backgroundColor = "0x000000FF"
    m.fraudLabel = m.top.CreateChild("Label")
    m.fraudLabel.translation = [100, 100]
    m.fraudLabel.font.size = 36
    m.fraudLabel.color = "0xFFFFFFFF"
    m.fraudLabel.text = "Fraudsters Flagged: 0"
    m.statsLabel = m.top.CreateChild("Label")
    m.statsLabel.translation = [100, 200]
    m.statsLabel.font.size = 24
    m.statsLabel.color = "0xFFFFFFFF"
    m.statsLabel.text = "Fraud Stats: Loading..."
    m.memePoster = m.top.CreateChild("Poster")
    m.memePoster.translation = [600, 100]
    m.memePoster.width = 300
    m.memePoster.height = 300
    m.memePoster.visible = false
    m.audioPlayer = m.top.CreateChild("Audio")
    m.audioPlayer.content = CreateObject("roSGNode", "ContentNode")
    m.audioTracks = [
        "pkg:/audio/epic_orchestra_choir.mp3",
        "pkg:/audio/mozart_dies_irae.mp3"
    ]
    m.pulseAnimation = m.top.CreateChild("Animation")
    m.pulseAnimation.duration = 1.0
    m.pulseAnimation.repeat = true
    m.pulseInterpolator = m.pulseAnimation.CreateChild("Vector2DFieldInterpolator")
    m.pulseInterpolator.key = [0.0, 0.5, 1.0]
    m.pulseInterpolator.keyValue = [[36, 36], [48, 48], [36, 36]]
    m.pulseInterpolator.fieldToInterp = m.fraudLabel.id + ".font.size"
    m.httpTask = CreateObject("roSGNode", "Node")
    m.httpTask.AddField("url", "string", false)
    m.httpTask.AddField("apiKey", "string", false)
    m.httpTask.AddField("response", "string", false)
    m.httpTask.ObserveField("response", "OnHttpResponse")
    m.httpTask.control = "RUN"
    m.timer = m.top.CreateChild("Timer")
    m.timer.duration = 10
    m.timer.repeat = true
    m.timer.ObserveField("fire", "FetchFraudData")
    m.timer.control = "start"
    m.knownIps = CreateObject("roArray", 0, true)
    FetchFraudData()
End Sub

Sub FetchFraudData()
    m.httpTask.url = "http://192.168.1.101:5000/fraud_data"
    m.httpTask.apiKey = "nsfr-secret-2025"
    m.httpTask.control = "RUN"
End Sub

Sub OnHttpResponse()
    response = m.httpTask.response
    if response = invalid or response = "" then
        m.fraudLabel.text = "Error Fetching Data"
        return
    end if
    data = ParseJson(response)
    if data = invalid then
        m.fraudLabel.text = "Error Parsing Data"
        return
    end if
    fraudCount = data.high_risk_ips.Count()
    m.fraudLabel.text = "Fraudsters Flagged: " + fraudCount.ToStr()
    statsText = "Fraud Stats:" + Chr(10)
    statsText = statsText + "XSS: " + data.xss.ToStr() + Chr(10)
    statsText = statsText + "Top Fraud: " + data.top_fraud
    m.statsLabel.text = statsText
    for each fraud in data.high_risk_ips
        if not IsIpKnown(fraud.ip) then
            m.knownIps.Push(fraud.ip)
            PlayRandomTrack()
            m.pulseAnimation.control = "start"
            if fraud.meme <> "" then
                m.memePoster.uri = fraud.meme
                m.memePoster.visible = true
            end if
        end if
    end for
End Sub

Function IsIpKnown(ip as String) as Boolean
    for each knownIp in m.knownIps
        if knownIp = ip then
            return true
        end if
    end for
    return false
End Function

Sub PlayRandomTrack()
    trackIndex = Rnd(m.audioTracks.Count()) - 1
    trackPath = m.audioTracks[trackIndex]
    content = m.audioPlayer.content
    content.url = trackPath
    m.audioPlayer.control = "play"
End Sub
