# Use first container to download all necessary packages/deps and copy only the required binaries into a new container
FROM ubuntu:jammy AS builder
WORKDIR /app

# Install necessary tools and clean up in the same layer
RUN apt-get update && apt-get install --no-install-recommends wget unzip openjdk-17-jre python3-pip -y && \
    pip install --no-cache-dir --upgrade objection && \
    wget https://dl.google.com/android/repository/commandlinetools-linux-10406996_latest.zip && \
    unzip commandlinetools-linux-10406996_latest.zip && \
    rm commandlinetools-linux-10406996_latest.zip && \
    mkdir -p android_sdk/cmdline-tools/latest && \
    mv cmdline-tools/* android_sdk/cmdline-tools/latest/ && \
    yes | android_sdk/cmdline-tools/latest/bin/sdkmanager "platform-tools" "build-tools;27.0.3" --channel=0 && \
    wget https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.8.1.jar -O ./apktool.jar && \
    wget https://raw.githubusercontent.com/iBotPeaches/Apktool/master/scripts/linux/apktool -O ./apktool && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y

FROM ubuntu:jammy 
WORKDIR /app

# Install necessary tools and clean up in the same layer
RUN apt-get update && apt-get install --no-install-recommends openjdk-17-jre python3-pip -y && \
    pip install --no-cache-dir --upgrade objection && \
    rm -rf /var/lib/apt/lists/* && \
    apt-get autoremove -y && \
    mkdir android_sdk

# Copy necessary files from builder stage
RUN pip3 install --upgrade objection
COPY --from=builder /app/android_sdk/build-tools/27.0.3/aapt2 /app/android_sdk
COPY --from=builder /app/android_sdk/build-tools/27.0.3/aapt /app/android_sdk
COPY --from=builder /app/android_sdk/build-tools/27.0.3/lib /app/android_sdk/lib
COPY --from=builder /app/android_sdk/build-tools/27.0.3/lib64 /app/android_sdk/lib64
COPY --from=builder /app/android_sdk/build-tools/27.0.3/apksigner /app/android_sdk
COPY --from=builder /app/android_sdk/build-tools/27.0.3/zipalign /app/android_sdk
COPY --from=builder /app/android_sdk/platform-tools/adb /app/android_sdk
COPY --from=builder /app/apktool /usr/local/bin/apktool
COPY --from=builder /app/apktool.jar /usr/local/bin/apktool.jar
RUN chmod +x /usr/local/bin/apktool*

ENV PATH=$PATH:/app/android_sdk

ENTRYPOINT ["/bin/sh", "-c"]